"""Exercise real server read views over the namespace's loopback API stream.

UpdateUser and PushUserStats use a separate authenticated existing-protocol
connection solely as setup for cursor/revision assertions. No operation retries
or host-network dependencies. CTest: waterwall.api_authentication_server_views.
"""

import json
from pathlib import Path
import re
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from api_server_probe import connect, exact, frame, require, response


TOKEN = "0123456789abcdef" * 4
MONITOR_TOKEN = "abcdef0123456789" * 4
LARGE_ID = "9007199254740993"
MAX_ID = "18446744073709551615"
USER_FIELDS = {"id", "gid", "enabled", "name", "email", "notes", "wireguard_allowed_ips",
               "record_stat_interval_ms", "limit", "time", "usage"}
SUMMARY_FIELDS = {"id", "gid", "enabled", "name_preview", "name_preview_state",
                  "traffic_limit", "usage", "time"}
PRIVATE_SENTINELS = ["NeverExposePassword", "NeverExposeProducerSecret", "users.json",
                     "password", "sha224", "sha256", "uuid", "wireguard_publickey"]


def decimal(value):
    require(isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]*", value) is not None,
            "An unsigned quantity was not a canonical decimal string")
    require(int(value) <= 0xFFFFFFFFFFFFFFFF, "Unsigned quantity overflow")


def leaves_are_decimal(value):
    if isinstance(value, dict):
        for child in value.values():
            leaves_are_decimal(child)
    else:
        decimal(value)


def query(stream, reader, identifier, operation, body=None, *, monitor=False, error=None):
    envelope = {"id": identifier,
                "auth": {"client": "monitor" if monitor else "auditor",
                         "token": MONITOR_TOKEN if monitor else TOKEN},
                "selector": {"config": "api-server", "node": "auth-db"},
                "operation": operation, "content_type": "application/json",
                "body_encoding": "utf8", "body": json.dumps(body if body is not None else {})}
    stream.sendall(frame(envelope))
    value = response(reader, identifier)
    require(value["error"] is None, "Server operation produced a gateway error")
    result = value["result"]
    require(result["content_type"] == "application/json" and result["body_encoding"] == "utf8",
            "Incorrect server view metadata")
    require(all(sentinel not in result["body"] for sentinel in PRIVATE_SENTINELS),
            "Server view leaked credentials or private storage details")
    decoded = json.loads(result["body"])
    if error is not None:
        require(result["code"] != 0 and decoded == {"error": {"code": error}},
                "Incorrect node-level error")
    else:
        require(result["code"] == 0, "Server operation rejected valid input")
    return decoded


def check_status(value, sessions):
    require(set(value) == {"database_loaded", "user_count", "configured_producer_count",
                           "session_record_count", "config_revision", "stats_revision", "primary_save"},
            "Status field allowlist changed")
    require(value["database_loaded"] is True and value["user_count"] == "3"
            and value["configured_producer_count"] == "1"
            and value["session_record_count"] == str(sessions), "Incorrect server counts")
    for field in ("config_revision", "stats_revision"):
        decimal(value[field])
    require(value["primary_save"] == {"last_result": "not_attempted", "last_attempt_age_ms": None,
                                      "last_success_age_ms": None}, "Read view initiated a save")


def check_detail(value, identifier):
    require(set(value) == {"config_revision", "stats_revision", "accounting_time_ms", "user"},
            "Detail metadata changed")
    for field in ("config_revision", "stats_revision", "accounting_time_ms"):
        decimal(value[field])
    user = value["user"]
    require(set(user) == USER_FIELDS and user["id"] == identifier, "Detail field allowlist/ID changed")
    require(isinstance(user["enabled"], bool), "Enabled is not a boolean")
    for field in ("id", "gid", "record_stat_interval_ms"):
        decimal(user[field])
    require(set(user["limit"]) == {"traffic", "bandwidth", "ips", "devices", "cons_in", "cons_out"},
            "Limit field allowlist changed")
    require(set(user["limit"]["traffic"]) == {"u", "d", "total"}
            and set(user["limit"]["bandwidth"]) == {"u", "d"}, "Traffic/bandwidth fields changed")
    require(set(user["time"]) == {"created_at_ms", "expire_at_ms", "expire_after_first_usage_ms",
                                  "first_usage_at_ms"}, "Detail time fields changed")
    require(set(user["usage"]) == {"u", "d"}, "Runtime gauges leaked into usage")
    for field in ("limit", "time", "usage"):
        leaves_are_decimal(user[field])
    return user


def check_page(value):
    require(set(value) == {"config_revision", "stats_revision", "accounting_time_ms", "total_users",
                           "users", "next_cursor"}, "List field allowlist changed")
    for field in ("config_revision", "stats_revision", "accounting_time_ms", "total_users"):
        decimal(value[field])
    require(value["total_users"] == "3", "Incorrect list count")
    require(value["next_cursor"] is None or
            re.fullmatch(r"[0-9a-f]{64}", value["next_cursor"]) is not None, "Invalid cursor representation")
    for user in value["users"]:
        require(set(user) == SUMMARY_FIELDS, "Summary exposed unexpected fields")
        require(set(user["traffic_limit"]) == {"u", "d", "total"}
                and set(user["usage"]) == {"u", "d"}
                and set(user["time"]) == {"expire_at_ms", "expire_after_first_usage_ms", "first_usage_at_ms"},
                "Summary nested field allowlist changed")
        require(isinstance(user["enabled"], bool) and user["name_preview_state"] == "complete"
                and isinstance(user["name_preview"], str), "Incorrect compact name preview")
        for field in ("id", "gid", "traffic_limit", "usage", "time"):
            leaves_are_decimal(user[field])
    return value


def protocol_request(stream, reader, request_type, correlation, body, token=bytes(64), expected=0):
    payload = body if isinstance(body, bytes) else json.dumps(body, separators=(",", ":")).encode("utf-8")
    request = token + struct.pack("!BII", request_type, correlation, len(payload)) + payload
    stream.sendall(struct.pack("!I", len(request)) + request)
    length = struct.unpack("!I", exact(reader, 4))[0]
    require(25 <= length <= 1024 * 1024, "Invalid authentication response length")
    message = exact(reader, length)
    config_revision, stats_revision = struct.unpack("!QQ", message[:16])
    response_type, returned_correlation, data_length = struct.unpack("!BII", message[16:25])
    require(response_type == expected and returned_correlation == correlation
            and data_length == length - 25, "Existing authentication operation failed")
    return message[25:], config_revision, stats_revision


def main():
    with connect() as stream, stream.makefile("rb") as reader:
        before = query(stream, reader, "initial", "status")
        check_status(before, 0)
        full = query(stream, reader, "large-id", "get-user", {"id": LARGE_ID})
        user = check_detail(full, LARGE_ID)
        require(user["gid"] == "7" and user["name"] == "Alice"
                and user["email"] == "alice@example.test" and user["notes"] == "Operator note"
                and user["wireguard_allowed_ips"] == "10.44.0.23/32"
                and user["record_stat_interval_ms"] == "1000", "Complete detail values changed")
        require(user["limit"] == {"traffic": {"u": "100", "d": "200", "total": "300"},
                                  "bandwidth": {"u": "10", "d": "20"}, "ips": "4", "devices": "2",
                                  "cons_in": "16", "cons_out": "17"}, "Configured limits changed")
        maximum = check_detail(query(stream, reader, "maximum-id", "get-user", {"id": MAX_ID}), MAX_ID)
        require(maximum["email"] == maximum["notes"] == maximum["wireguard_allowed_ips"] == "",
                "Absent optional fields must be empty strings")
        query(stream, reader, "missing", "get-user", {"id": "123"}, error="not_found")

        first = check_page(query(stream, reader, "page-1", "list-users", {"limit": 1}))
        require(len(first["users"]) == 1 and first["next_cursor"] is not None, "First page did not advance")
        second = check_page(query(stream, reader, "page-2", "list-users",
                                  {"limit": 2, "cursor": first["next_cursor"]}))
        all_ids = [item["id"] for item in first["users"] + second["users"]]
        require(len(all_ids) == len(set(all_ids)) == 3 and set(all_ids) == {LARGE_ID, MAX_ID, "42"}
                and second["next_cursor"] is None, "Traversal omitted or repeated an account")
        check_status(query(stream, reader, "unchanged", "status"), 0)

        for operation, body in (("get-user", {"id": LARGE_ID}),
                                ("list-users", {"cursor": first["next_cursor"]})):
            identifier = "denied-" + operation
            envelope = {"id": identifier, "auth": {"client": "monitor", "token": MONITOR_TOKEN},
                        "selector": {"config": "api-server", "node": "auth-db"},
                        "operation": operation, "content_type": "application/json",
                        "body_encoding": "utf8", "body": json.dumps(body)}
            stream.sendall(frame(envelope))
            denied = response(reader, identifier)
            require(denied["error"]["code"] == "forbidden" and denied["result"] is None,
                    "Status permission granted access to account operations")
        check_status(query(stream, reader, "monitor-status", "status", monitor=True), 0)

        with connect(29382) as control, control.makefile("rb") as control_reader:
            session, _, _ = protocol_request(control, control_reader, 10, 1,
                                             {"name": "fixture-writer", "secret": "NeverExposeProducerSecret"},
                                             expected=4)
            require(len(session) == 128, "Authentication session/epoch missing")
            token, epoch = session[:64], session[64:].decode("ascii")
            check_status(query(stream, reader, "session-status", "status"), 1)
            require(token.decode("ascii") not in json.dumps(full) and epoch not in json.dumps(full),
                    "Account detail exposed authentication state")

            # A real accepted usage batch changes only the statistics revision.
            batch = json.dumps({"epoch": epoch, "sequence": "1", "users": [
                {"id": all_ids[1], "up": "13", "down": "29",
                 "first-usage-at-ms": first["accounting_time_ms"]}]}, separators=(",", ":")).encode("utf-8")
            _, config_revision, stats_revision = protocol_request(control, control_reader, 11, 2, batch, token)
            require(str(config_revision) == first["config_revision"]
                    and stats_revision == int(first["stats_revision"]) + 1, "Usage changed configuration revision")
            continued = check_page(query(stream, reader, "after-usage", "list-users",
                                         {"limit": 2, "cursor": first["next_cursor"]}))
            require(continued["stats_revision"] == str(stats_revision), "Continuation hid new statistics")
            changed = next(item for item in continued["users"] if item["id"] == all_ids[1])
            require(changed["usage"] == {"u": "13", "d": "29"}, "Continuation did not include accepted usage")
            _, replay_config, replay_stats = protocol_request(control, control_reader, 11, 3, batch, token)
            require((replay_config, replay_stats) == (config_revision, stats_revision), "Replay changed revisions")
            replayed = check_page(query(stream, reader, "after-replay", "list-users",
                                        {"limit": 2, "cursor": first["next_cursor"]}))
            require(replayed["users"] == continued["users"], "Replay double-counted usage")

            # A real configuration transaction invalidates the previous cursor.
            _, edited_config, edited_stats = protocol_request(control, control_reader, 7, 4,
                                                              {"id": LARGE_ID, "name": "Alice edited"}, token)
            require(edited_config == config_revision + 1 and edited_stats == stats_revision,
                    "Configuration edit changed the wrong revision")
            query(stream, reader, "stale", "list-users", {"cursor": first["next_cursor"]}, error="stale_cursor")
            edited = query(stream, reader, "edited-user", "get-user", {"id": LARGE_ID})
            require(check_detail(edited, LARGE_ID)["name"] == "Alice edited"
                    and edited["config_revision"] == str(edited_config), "Detail missed committed edit")
            restarted = check_page(query(stream, reader, "restart", "list-users"))
            require(len(restarted["users"]) == 3 and restarted["next_cursor"] is None,
                    "New traversal failed after configuration edit")
            check_status(query(stream, reader, "final", "status"), 1)


main()
