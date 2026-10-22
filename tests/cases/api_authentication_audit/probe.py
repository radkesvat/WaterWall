"""Audit actual API/producer commits and refusals over private loopback.

Only readiness and read-only observation poll. Every administrative request is
submitted once. CTest: waterwall.api_authentication_audit.
"""

import json
from pathlib import Path
import re
import struct
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import api_server_probe as api

TOKEN = "0123456789abcdef" * 4
SECRETS = [TOKEN, "PRIVATE_PRODUCER_SECRET_SENTINEL", "PRIVATE_INITIAL_PASSWORD_SENTINEL",
           "PRIVATE_ROTATED_PASSWORD_SENTINEL", "PRIVATE_MALFORMED_PASSWORD_SENTINEL",
           "PRIVATE_PRODUCER_PASSWORD_SENTINEL", "PRIVATE_NOTE_SENTINEL"]


def envelope(identifier, operation, body):
    return {"id": identifier, "auth": {"client": "admin", "token": TOKEN},
            "selector": {"config": "audit-fixture", "node": "accounts"},
            "operation": operation, "content_type": "application/json", "body_encoding": "utf8",
            "body": body if isinstance(body, str) else json.dumps(body)}


def query(stream, reader, identifier, operation, body=None, error=None):
    stream.sendall(api.frame(envelope(identifier, operation, {} if body is None else body)))
    response = api.response(reader, identifier)
    api.require(response["error"] is None, "Unexpected gateway refusal")
    result = response["result"]
    decoded = json.loads(result["body"])
    if error is None:
        api.require(result["code"] == 0, "Valid operation failed")
    else:
        api.require(result["code"] != 0 and decoded == {"error": {"code": error}}, "Wrong node refusal")
    return decoded


def protocol(stream, reader, operation, correlation, body, token=bytes(64), expected=0):
    payload = body if isinstance(body, bytes) else json.dumps(body).encode()
    message = token + struct.pack("!BII", operation, correlation, len(payload)) + payload
    stream.sendall(struct.pack("!I", len(message)) + message)
    size = struct.unpack("!I", api.exact(reader, 4))[0]
    api.require(25 <= size <= 65536, "Invalid producer reply size")
    response = api.exact(reader, size)
    code, returned_id, length = struct.unpack("!BII", response[16:25])
    api.require(code == expected and returned_id == correlation and length == size - 25, "Producer result changed")
    return response[25:]


def main():
    with api.connect() as stream, stream.makefile("rb") as reader:
        initial = query(stream, reader, "ready", "status")
        api.require(initial["audit"] == {"enabled": True, "healthy": True, "queued_records": "0",
                                         "written_records": "0", "dropped_records": "0", "suppressed_rejections": "0", "write_failures": "0",
                                         "last_error": None}, "Initial audit status changed")
        created = query(stream, reader, "create", "create-user",
                        {"id": "42", "password": SECRETS[2], "config": {"name": "Alice"}})
        updated = query(stream, reader, "update", "update-user",
                        {"id": "42", "if_match": created["edit_token"],
                         "patch": {"enabled": False, "notes": SECRETS[6]}})
        rotated = query(stream, reader, "rotate", "change-user-password",
                        {"id": "42", "if_match": updated["edit_token"], "password": SECRETS[3]})
        query(stream, reader, "conflict", "update-user",
              {"id": "42", "if_match": created["edit_token"], "patch": {"enabled": True}}, error="conflict")
        query(stream, reader, "malformed", "change-user-password",
              '{"password":"' + SECRETS[4] + '",', error="invalid_request")

        with api.connect(29382) as producer, producer.makefile("rb") as producer_reader:
            session = protocol(producer, producer_reader, 10, 1,
                               {"name": "fixture-producer", "secret": SECRETS[1]}, expected=4)
            api.require(len(session) == 128, "Producer session failed")
            token = session[:64]
            protocol(producer, producer_reader, 6, 2, {"id": "43", "password": SECRETS[5]}, token)
            protocol(producer, producer_reader, 7, 3, {"id": "43", "name": "Producer account"}, token)
            protocol(producer, producer_reader, 6, 4, {"id": "43", "password": "duplicate"}, token, expected=255)
            protocol(producer, producer_reader, 7, 5, b'{"password":"PRIVATE_MALFORMED_PASSWORD_SENTINEL",',
                     token, expected=255)

        current = query(stream, reader, "current", "get-user", {"id": "42"})
        # Discard delivery while independently establishing that this one attempt
        # committed. We never infer commit from socket timing or retry the write.
        with api.connect() as abandoned:
            abandoned.sendall(api.frame(envelope("abandoned", "update-user",
                              {"id": "42", "if_match": current["edit_token"], "patch": {"enabled": True}})))
            deadline = time.monotonic() + 5
            while True:
                observed = query(stream, reader, "observe", "get-user", {"id": "42"})
                if observed["user"]["enabled"]:
                    break
                api.require(time.monotonic() < deadline, "Discarded-reply operation did not commit")
                time.sleep(0.01)

        deadline = time.monotonic() + 5
        while True:
            health = query(stream, reader, "health", "status")["audit"]
            api.require(health["healthy"] and health["dropped_records"] == "0" and health["write_failures"] == "0",
                        "Healthy audit lost an event")
            if int(health["written_records"]) + int(health["suppressed_rejections"]) == 10 and health["queued_records"] == "0":
                break
            api.require(time.monotonic() < deadline, "Background audit writer did not flush all outcomes")
            time.sleep(0.01)

    raw = Path("administration.jsonl").read_text(encoding="utf-8")
    api.require(raw.endswith("\n") and all(secret not in raw for secret in SECRETS), "Audit leaked input or partial record")
    rows = [json.loads(line) for line in raw.splitlines()]
    rejections = [row for row in rows if row["outcome"] == "rejected"]
    api.require(len(rows) + int(health["suppressed_rejections"]) == 10 and 1 <= len(rejections) <= 4,
                "Sampled rejections and intentional suppression do not account for all outcomes")
    fields = {"timestamp_ms", "server_instance", "sequence", "config", "node", "source", "actor",
              "gateway_config", "gateway_node", "operation", "user_id", "outcome", "error",
              "config_revision", "fields", "identity_truncated"}
    for index, row in enumerate(rows, 1):
        expected_fields = fields | ({"node_suppressed_rejections"} if row["outcome"] == "rejected" else set())
        api.require(set(row) == expected_fields and row["sequence"] == str(index), "Audit schema or accepted order changed")
        if row["outcome"] == "rejected":
            api.require(re.fullmatch(r"0|[1-9][0-9]*", row["node_suppressed_rejections"]) is not None,
                        "Node-wide suppression count is not an exact unsigned decimal")
        api.require(re.fullmatch(r"[0-9a-f]{32}", row["server_instance"]) is not None
                    and row["server_instance"] == initial["edit_token"][:32], "Wrong server identity")
        api.require(row["config"] == "audit-fixture" and row["node"] == "accounts"
                    and row["identity_truncated"] is False and int(row["timestamp_ms"]) > 0, "Wrong event metadata")
        if row["source"] == "api":
            api.require((row["actor"], row["gateway_config"], row["gateway_node"]) ==
                        ("admin", "audit-fixture", "api"), "Gateway/operator identity was not propagated")
        else:
            api.require(row["source"] == "producer" and row["actor"] == "fixture-producer"
                        and row["gateway_config"] is None and row["gateway_node"] is None, "Wrong producer identity")
    committed = [row for row in rows if row["outcome"] == "committed"]
    api.require([row["operation"] for row in committed] ==
                ["create-user", "update-user", "change-user-password", "AddNewUser", "UpdateUser", "update-user"],
                "Audit omitted, duplicated or reordered a committed operation")
    api.require(committed[1]["fields"] == ["enabled", "notes"] or
                set(committed[1]["fields"]) == {"enabled", "notes"}, "Update audit omitted field names")
    api.require(committed[2]["fields"] == ["credentials"] and rejections[0]["error"] == "conflict",
                "Password/conflict event classification changed")
    api.require(all(row["error"] in {"conflict", "invalid_request", "user-id-exists", "invalid-user-json"}
                    for row in rejections), "Sampled rejection classification changed")
    revisions = [int(row["config_revision"]) for row in rows if row["outcome"] == "committed"]
    api.require(revisions == list(range(int(initial["config_revision"]) + 1,
                                        int(initial["config_revision"]) + 7)), "Audit lost committed revision order")
    api.require(all(row["config_revision"] is None for row in rows if row["outcome"] == "rejected"),
                "Rejected event claimed a committed revision")


if __name__ == "__main__":
    main()
