"""Exercise real server read views and account mutations over private loopback.

UpdateUser and PushUserStats use a separate authenticated existing-protocol
connection solely as setup for cursor/revision assertions. No automatic operation retries
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
EDITOR_TOKEN = "fedcba9876543210" * 4
CREATOR_TOKEN = "13579bdf02468ace" * 4
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


def request(identifier, operation, body=None, *, monitor=False, editor=False, creator=False):
    return {"id": identifier,
                "auth": {"client": "creator" if creator else "editor" if editor else "monitor" if monitor else "auditor",
                         "token": CREATOR_TOKEN if creator else EDITOR_TOKEN if editor else MONITOR_TOKEN if monitor else TOKEN},
                "selector": {"config": "api-server", "node": "auth-db"},
                "operation": operation, "content_type": "application/json",
                "body_encoding": "utf8", "body": json.dumps(body if body is not None else {})}


def query(stream, reader, identifier, operation, body=None, *, monitor=False, editor=False, creator=False, error=None,
          max_envelope=1024 * 1024):
    envelope = request(identifier, operation, body, monitor=monitor, editor=editor, creator=creator)
    stream.sendall(frame(envelope))
    value = response(reader, identifier, max_envelope)
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


def check_token(value):
    token = value["edit_token"]
    require(isinstance(token, str) and re.fullmatch(r"[0-9a-f]{48}", token) is not None,
            "Invalid edit token representation")
    require(int(token[32:], 16) == int(value["config_revision"]), "Token/revision snapshot mismatch")


def check_ack(value, identifier, previous_token):
    require(set(value) == {"id", "config_revision", "edit_token"} and value["id"] == identifier,
            "Mutation acknowledgement schema changed")
    decimal(value["config_revision"])
    check_token(value)
    require(value["edit_token"][:32] == previous_token[:32]
            and int(value["config_revision"]) == int(previous_token[32:], 16) + 1,
            "Mutation did not publish exactly its committed revision")


def check_status(value, sessions, users=3):
    require(set(value) == {"database_loaded", "user_count", "configured_producer_count",
                           "session_record_count", "config_revision", "stats_revision", "primary_save", "edit_token"},
            "Status field allowlist changed")
    check_token(value)
    require(value["database_loaded"] is True and value["user_count"] == str(users)
            and value["configured_producer_count"] == "1"
            and value["session_record_count"] == str(sessions), "Incorrect server counts")
    for field in ("config_revision", "stats_revision"):
        decimal(value[field])
    require(value["primary_save"] == {"last_result": "not_attempted", "last_attempt_age_ms": None,
                                      "last_success_age_ms": None}, "Read view initiated a save")


def check_detail(value, identifier):
    require(set(value) == {"config_revision", "stats_revision", "accounting_time_ms", "user", "edit_token"},
            "Detail metadata changed")
    check_token(value)
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


def check_page(value, users=3):
    require(set(value) == {"config_revision", "stats_revision", "accounting_time_ms", "total_users",
                           "users", "next_cursor", "edit_token"}, "List field allowlist changed")
    check_token(value)
    for field in ("config_revision", "stats_revision", "accounting_time_ms", "total_users"):
        decimal(value[field])
    require(value["total_users"] == str(users), "Incorrect list count")
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
        require(full["edit_token"] == before["edit_token"], "Read token changed without a configuration edit")
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
        require(first["edit_token"] == full["edit_token"], "List token differs from matching detail/status")
        require(len(first["users"]) == 1 and first["next_cursor"] is not None, "First page did not advance")
        require(first["next_cursor"][:48] == first["edit_token"], "Edit token changed cursor representation")
        second = check_page(query(stream, reader, "page-2", "list-users",
                                  {"limit": 2, "cursor": first["next_cursor"]}))
        all_ids = [item["id"] for item in first["users"] + second["users"]]
        require(len(all_ids) == len(set(all_ids)) == 3 and set(all_ids) == {LARGE_ID, MAX_ID, "42"}
                and second["next_cursor"] is None, "Traversal omitted or repeated an account")
        check_status(query(stream, reader, "unchanged", "status"), 0)

        for operation, body in (("get-user", {"id": LARGE_ID}),
                                ("list-users", {"cursor": first["next_cursor"]}),
                                ("update-user", {"id": LARGE_ID, "if_match": first["edit_token"],
                                                 "patch": {"enabled": False}})):
            identifier = "denied-" + operation
            stream.sendall(frame(request(identifier, operation, body, monitor=True)))
            denied = response(reader, identifier)
            require(denied["error"]["code"] == "forbidden" and denied["result"] is None,
                    "Status permission granted access to account operations")
        stream.sendall(frame(request("auditor-denied-write", "update-user",
                                    {"id": LARGE_ID, "if_match": first["edit_token"],
                                     "patch": {"enabled": False}})))
        denied = response(reader, "auditor-denied-write")
        require(denied["error"]["code"] == "forbidden" and denied["result"] is None,
                "Read permissions granted an implicit write permission")
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
            require(continued["edit_token"] == first["edit_token"], "Usage invalidated the edit token")
            changed = next(item for item in continued["users"] if item["id"] == all_ids[1])
            require(changed["usage"] == {"u": "13", "d": "29"}, "Continuation did not include accepted usage")
            _, replay_config, replay_stats = protocol_request(control, control_reader, 11, 3, batch, token)
            require((replay_config, replay_stats) == (config_revision, stats_revision), "Replay changed revisions")
            replayed = check_page(query(stream, reader, "after-replay", "list-users",
                                        {"limit": 2, "cursor": first["next_cursor"]}))
            require(replayed["users"] == continued["users"], "Replay double-counted usage")
            require(replayed["edit_token"] == first["edit_token"], "Exact replay changed the edit token")

            # A real configuration transaction invalidates the previous cursor.
            _, edited_config, edited_stats = protocol_request(control, control_reader, 7, 4,
                                                              {"id": LARGE_ID, "name": "Alice edited"}, token)
            require(edited_config == config_revision + 1 and edited_stats == stats_revision,
                    "Configuration edit changed the wrong revision")
            query(stream, reader, "stale", "list-users", {"cursor": first["next_cursor"]}, error="stale_cursor")
            query(stream, reader, "protocol-conflict", "update-user",
                  {"id": LARGE_ID, "if_match": first["edit_token"], "patch": {"enabled": False}},
                  editor=True, error="conflict")
            edited = query(stream, reader, "edited-user", "get-user", {"id": LARGE_ID})
            require(check_detail(edited, LARGE_ID)["name"] == "Alice edited"
                    and edited["config_revision"] == str(edited_config), "Detail missed committed edit")
            restarted = check_page(query(stream, reader, "restart", "list-users"))
            require(len(restarted["users"]) == 3 and restarted["next_cursor"] is None,
                    "New traversal failed after configuration edit")
            conditional_edits(stream, reader, control, control_reader, token, edited)
            create_accounts(stream, reader, control, control_reader, token)
            check_status(query(stream, reader, "final", "status"), 1, 7)


def conditional_edits(stream, reader, control, control_reader, session_token, previous):
    current = query(stream, reader, "editor-read", "get-user", {"id": LARGE_ID}, editor=True)
    saved = check_detail(current, LARGE_ID)
    saved_maximum = check_detail(query(stream, reader, "accounting-before-edit", "get-user", {"id": MAX_ID},
                                      editor=True), MAX_ID)
    require(current["edit_token"] == previous["edit_token"], "Editor read an inconsistent token")
    token = current["edit_token"]
    wrong_instance = ("1" if token[0] == "0" else "0") + token[1:]
    query(stream, reader, "instance-conflict", "update-user",
          {"id": LARGE_ID, "if_match": wrong_instance, "patch": {"enabled": False}},
          editor=True, error="conflict")
    query(stream, reader, "protected-field", "update-user",
          {"id": LARGE_ID, "if_match": token, "patch": {"usage": {"u": "0"}}},
          editor=True, error="invalid_request")

    acknowledgement = query(stream, reader, "conditional-edit", "update-user",
                            {"id": LARGE_ID, "if_match": token,
                             "patch": {"enabled": False, "limit": {"traffic": {"total": "999"}},
                                       "time": {"expire_at_ms": "1"}}}, editor=True)
    check_ack(acknowledgement, LARGE_ID, token)
    after = query(stream, reader, "after-edit", "get-user", {"id": LARGE_ID}, editor=True)
    expected = json.loads(json.dumps(saved))
    expected["enabled"] = False
    expected["limit"]["traffic"]["total"] = "999"
    expected["time"]["expire_at_ms"] = "1"
    require(check_detail(after, LARGE_ID) == expected
            and after["stats_revision"] == current["stats_revision"]
            and after["edit_token"] == acknowledgement["edit_token"],
            "Sparse edit changed omitted configuration, accounting or its acknowledgement")
    query(stream, reader, "old-token", "update-user",
          {"id": LARGE_ID, "if_match": token, "patch": {"enabled": True}}, editor=True, error="conflict")

    # Disabled, expired accounts remain editable. Same-value edits still revise.
    same = query(stream, reader, "same-value", "update-user",
                 {"id": LARGE_ID, "if_match": after["edit_token"], "patch": {"enabled": False}}, editor=True)
    check_ack(same, LARGE_ID, after["edit_token"])
    unrelated = query(stream, reader, "unrelated-account", "update-user",
                      {"id": MAX_ID, "if_match": same["edit_token"], "patch": {"notes": "Other account edit"}},
                      editor=True)
    check_ack(unrelated, MAX_ID, same["edit_token"])
    query(stream, reader, "unrelated-conflict", "update-user",
          {"id": LARGE_ID, "if_match": same["edit_token"], "patch": {"enabled": True}},
          editor=True, error="conflict")

    # The response must fit the minimum gateway cap even with a fully escaped
    # maximum-length request ID. Do not read details through this small endpoint.
    with connect(29381) as small, small.makefile("rb") as small_reader:
        compact = query(small, small_reader, "\x01" * 64, "update-user",
                        {"id": MAX_ID, "if_match": unrelated["edit_token"],
                         "patch": {"notes": "Bounded acknowledgement"}}, editor=True, max_envelope=1024)
        check_ack(compact, MAX_ID, unrelated["edit_token"])

    # Discard the entire result body after the prefix proves publication. The
    # application cannot use that lost acknowledgement as its success oracle.
    lost_request = {"id": MAX_ID, "if_match": compact["edit_token"],
                    "patch": {"notes": "Unobserved reply committed"}}
    with connect() as abandoned, abandoned.makefile("rb") as abandoned_reader:
        abandoned.sendall(frame(request("discarded-result", "update-user", lost_request, editor=True)))
        length = struct.unpack("!I", exact(abandoned_reader, 4))[0]
        require(0 < length <= 1024, "Unbounded mutation acknowledgement")
        # Closing both handles discards the unread result body.
    reread = query(stream, reader, "reread-after-disconnect", "get-user", {"id": MAX_ID}, editor=True)
    changed = check_detail(reread, MAX_ID)
    expected_maximum = dict(saved_maximum, notes="Unobserved reply committed")
    require(changed == expected_maximum and changed["usage"] == {"u": "13", "d": "29"}
            and int(reread["config_revision"]) == int(compact["config_revision"]) + 1,
            "Fresh read failed to resolve the lost update response or accounting was overwritten")
    query(stream, reader, "lost-old-token", "update-user", lost_request, editor=True, error="conflict")

    # A later authorized producer edit remains a later write under its schema.
    _, protocol_revision, protocol_stats = protocol_request(control, control_reader, 7, 5,
                                                            {"id": MAX_ID, "notes": "Later producer edit"},
                                                            session_token)
    last = query(stream, reader, "after-later-protocol", "get-user", {"id": MAX_ID}, editor=True)
    require(check_detail(last, MAX_ID)["notes"] == "Later producer edit"
            and int(last["config_revision"]) == protocol_revision == int(reread["config_revision"]) + 1
            and int(last["stats_revision"]) == protocol_stats == int(reread["stats_revision"]),
            "Producer/API transaction ordering changed")


def create_accounts(stream, reader, control, control_reader, session_token):
    before = query(stream, reader, "before-create", "status")
    old_page = query(stream, reader, "before-create-page", "list-users", {"limit": 1})
    existing = {identifier: check_detail(query(stream, reader, "preserve-" + identifier,
                                             "get-user", {"id": identifier}), identifier)
                for identifier in (LARGE_ID, MAX_ID, "42")}
    candidate = {"id": "43", "password": "NeverExposePasswordCreated"}
    for label, role in (("monitor", {"monitor": True}), ("auditor", {}), ("editor", {"editor": True})):
        correlation = label + "-denied-create"
        stream.sendall(frame(request(correlation, "create-user", candidate, **role)))
        denied = response(reader, correlation)
        require(denied["error"]["code"] == "forbidden" and denied["result"] is None,
                "Read or update permissions implicitly granted account creation")
    with connect() as producer_api, producer_api.makefile("rb") as producer_reader:
        envelope = request("producer-denied-create", "create-user", candidate)
        envelope["auth"] = {"client": "fixture-writer", "token": "NeverExposeProducerSecret"}
        producer_api.sendall(frame(envelope))
        denied = response(producer_reader, "producer-denied-create")
        require(denied["error"]["code"] == "unauthorized" and denied["result"] is None,
                "Producer credentials granted gateway access")

    for index, invalid in enumerate((
            {"id": "43"}, {"id": "43", "password": ""},
            {"id": 43, "password": "fixture"},
            dict(candidate, if_match=before["edit_token"]),
            dict(candidate, config={"password": "fixture"}),
            dict(candidate, config={"limit": {}}))):
        query(stream, reader, "invalid-create-" + str(index), "create-user", invalid,
              creator=True, error="invalid_request")
    unchanged = query(stream, reader, "create-refusals", "status")
    require(unchanged == before, "Creation refusal changed state or save telemetry")

    ack = query(stream, reader, "create-default", "create-user", candidate, creator=True)
    check_ack(ack, "43", before["edit_token"])
    detail = query(stream, reader, "created-default", "get-user", {"id": "43"}, creator=True)
    fresh = check_detail(detail, "43")
    require(fresh["gid"] == "0" and fresh["enabled"] is True
            and all(fresh[field] == "" for field in ("name", "email", "notes", "wireguard_allowed_ips"))
            and fresh["record_stat_interval_ms"] == "120000"
            and fresh["limit"] == {"traffic": {"u": "0", "d": "0", "total": "0"},
                                    "bandwidth": {"u": "0", "d": "0"}, "ips": "0", "devices": "0",
                                    "cons_in": "0", "cons_out": "0"}
            and fresh["usage"] == {"u": "0", "d": "0"}
            and int(fresh["time"]["created_at_ms"]) > 0
            and all(fresh["time"][field] == "0" for field in
                    ("expire_at_ms", "expire_after_first_usage_ms", "first_usage_at_ms"))
            and detail["edit_token"] == ack["edit_token"]
            and detail["stats_revision"] == before["stats_revision"],
            "Fresh account defaults, accounting, creation time or transaction token changed")
    query(stream, reader, "create-replay", "create-user", candidate, creator=True, error="id_exists")
    query(stream, reader, "create-id-first", "create-user",
          {"id": "43", "password": "NeverExposePasswordAlice", "config": {"name": "Alice edited"}},
          creator=True, error="id_exists")
    query(stream, reader, "creation-stales-cursor", "list-users",
          {"cursor": old_page["next_cursor"]}, error="stale_cursor")
    query(stream, reader, "creation-stales-edit", "update-user",
          {"id": LARGE_ID, "if_match": before["edit_token"], "patch": {"enabled": True}},
          editor=True, error="conflict")

    # The existing protocol resolves the exact supplied password, and its add
    # collides without saving or changing the API-created identity.
    payload, revision, stats = protocol_request(control, control_reader, 5, 20,
                                                candidate["password"].encode("utf-8"), session_token, expected=2)
    # The existing producer serializer keeps its numeric-or-string import schema.
    require(str(json.loads(payload)["id"]) == "43" and str(revision) == ack["config_revision"]
            and str(stats) == before["stats_revision"], "Created credential is unavailable to the existing protocol")
    refusal, revision, _ = protocol_request(control, control_reader, 6, 21,
                                            {"id": "43", "password": "NeverExposePasswordReplacement"},
                                            session_token, expected=255)
    require(refusal == b"user-id-exists" and str(revision) == ack["config_revision"],
            "Producer addition replaced an API-created account or changed revision")

    empty_ack = query(stream, reader, "create-empty-config", "create-user",
                      {"id": "44", "password": "NeverExposePasswordEmptyConfig", "config": {}}, creator=True)
    check_ack(empty_ack, "44", ack["edit_token"])
    empty = check_detail(query(stream, reader, "empty-config-detail", "get-user", {"id": "44"}, creator=True), "44")
    require(dict(empty, id="43", time=fresh["time"]) == fresh, "Empty config changed constructor defaults")

    configured_id = "9007199254740994"
    config = {"name": "New staged account", "email": "created@example.test", "notes": "New account note",
              "wireguard_allowed_ips": "10.55.3.7/24", "gid": MAX_ID, "enabled": False,
              "record_stat_interval_ms": "0",
              "limit": {"traffic": {"u": "10", "d": "20", "total": MAX_ID},
                        "bandwidth": {"u": "30", "d": "40"}, "ips": "50", "devices": "60",
                        "cons_in": "70", "cons_out": "80"},
              "time": {"expire_at_ms": "0", "expire_after_first_usage_ms": "90"}}
    # The same compact response schema is used by updates and creation.
    with connect(29381) as small, small.makefile("rb") as small_reader:
        configured_ack = query(small, small_reader, "\x01" * 64, "create-user",
                               {"id": configured_id, "password": "NeverExposePasswordConfigured", "config": config},
                               creator=True, max_envelope=1024)
    check_ack(configured_ack, configured_id, empty_ack["edit_token"])
    configured = check_detail(query(stream, reader, "configured-detail", "get-user", {"id": configured_id},
                                    creator=True), configured_id)
    expected_config = dict(config, wireguard_allowed_ips="10.55.3.0/24")
    require(all(configured[field] == expected_config[field] for field in config if field != "time")
            and all(configured["time"][field] == value for field, value in config["time"].items())
            and configured["time"]["first_usage_at_ms"] == "0" and configured["usage"] == {"u": "0", "d": "0"},
            "Initial public configuration, Allowed-IP normalization or clean accounting changed")
    for label, conflict, expected_error in (
            ("name", {"name": config["name"]}, "name_exists"),
            ("range", {"wireguard_allowed_ips": "10.55.3.128/25"}, "allowed_ips_overlap"),
            ("invalid-range", {"wireguard_allowed_ips": "bad-range"}, "invalid_allowed_ips")):
        query(stream, reader, "create-conflict-" + label, "create-user",
              {"id": "45", "password": "NeverExposePasswordConflict", "config": conflict},
              creator=True, error=expected_error)
    query(stream, reader, "create-credentials-conflict", "create-user",
          {"id": "45", "password": candidate["password"]}, creator=True, error="credentials_exist")

    # A discarded response does not undo publication. An identical request is
    # still create-only, and a public read cannot establish password ownership.
    lost = {"id": "45", "password": "NeverExposePasswordLostCreation", "config": {"enabled": False}}
    with connect() as abandoned, abandoned.makefile("rb") as abandoned_reader:
        abandoned.sendall(frame(request("discarded-create", "create-user", lost, creator=True)))
        length = struct.unpack("!I", exact(abandoned_reader, 4))[0]
        require(0 < length <= 1024, "Unbounded creation acknowledgement")
    recovered = query(stream, reader, "reread-created", "get-user", {"id": "45"}, creator=True)
    require(check_detail(recovered, "45")["enabled"] is False
            and int(recovered["config_revision"]) == int(configured_ack["config_revision"]) + 1,
            "Lost creation acknowledgement removed or duplicated the committed account")
    query(stream, reader, "lost-create-retry", "create-user", lost, creator=True, error="id_exists")
    for identifier, saved in existing.items():
        require(check_detail(query(stream, reader, "preserved-" + identifier, "get-user", {"id": identifier}),
                             identifier) == saved, "Account creation changed an existing account")
    final = query(stream, reader, "created-status", "status")
    check_status(final, 1, 7)
    page = check_page(query(stream, reader, "created-list", "list-users"), 7)
    require(final["edit_token"] == recovered["edit_token"] == page["edit_token"]
            and final["stats_revision"] == before["stats_revision"]
            and {user["id"] for user in page["users"]} == {LARGE_ID, MAX_ID, "42", "43", "44", configured_id, "45"},
            "Creation read coherence, count, revisions or index publication changed")


main()
