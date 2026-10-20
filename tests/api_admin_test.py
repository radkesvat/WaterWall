#!/usr/bin/env python3
"""Administration CLI regression coverage with one deterministic transport seam.

Exercises the actual argument, password, request and output paths without a
network. The separate namespace fixture exercises the real CLI and server.
CTest: waterwall.api_admin_client (production support lane).
"""

import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tunnels/APIServer/client"))
import ww_admin as CLIENT


API_TOKEN = "ab" * 32
EDIT_TOKEN = "12" * 16 + "0000000000000054"
LARGE_ID = "9007199254740993"
MAX_ID = "18446744073709551615"
PASSWORD = "  PRIVATE_PASSWORD_SENTINEL_é\n"
CURSOR1 = EDIT_TOKEN + "0000000000000001"
CURSOR2 = EDIT_TOKEN + "0000000000000002"


def metadata():
    return {"config_revision": "84", "stats_revision": "6", "accounting_time_ms": "1700000000000",
            "edit_token": EDIT_TOKEN}


def acknowledgement(identifier=LARGE_ID):
    return {"id": identifier, "config_revision": "84", "edit_token": EDIT_TOKEN}


def detail(identifier=LARGE_ID):
    return {**metadata(), "user": {
        "id": identifier, "gid": "0", "enabled": True, "name": "Alice", "email": "", "notes": "",
        "wireguard_allowed_ips": "", "record_stat_interval_ms": "120000",
        "limit": {"traffic": {"u": "0", "d": "0", "total": "0"},
                  "bandwidth": {"u": "0", "d": "0"}, "ips": "0", "devices": "0", "cons_in": "0", "cons_out": "0"},
        "time": {"created_at_ms": "0", "expire_at_ms": "0", "expire_after_first_usage_ms": "0", "first_usage_at_ms": "0"},
        "usage": {"u": "0", "d": "0"}}}


def page(identifier=LARGE_ID, cursor=None):
    user = detail(identifier)["user"]
    summary = {key: user[key] for key in ("id", "gid", "enabled", "usage")}
    summary.update(name_preview=user["name"], name_preview_state="complete", traffic_limit=user["limit"]["traffic"],
                   time={key: value for key, value in user["time"].items() if key != "created_at_ms"})
    return {**metadata(), "total_users": "3", "users": [summary], "next_cursor": cursor}


def status():
    return {"database_loaded": True, "user_count": "3", "configured_producer_count": "1",
            "session_record_count": "0", "config_revision": "84", "stats_revision": "6", "edit_token": EDIT_TOKEN,
            "primary_save": {"last_result": "not_attempted", "last_attempt_age_ms": None, "last_success_age_ms": None},
            "audit": {"enabled": False, "healthy": True, "queued_records": "0", "written_records": "0",
                      "dropped_records": "0", "write_failures": "0", "last_error": None}}


def reply(body, code=0):
    return {"error": None, "result": {"code": code, "content_type": "application/json", "body_encoding": "utf8",
                                      "body": json.dumps(body, ensure_ascii=False)}}


class AdminTest(unittest.TestCase):
    def invoke(self, command, responses=None, error=None, stdin=b"", options=None, prompts=None, tty=False,
               output_failure=False):
        argv = ["--client", "admin", "--token-env", "WW_TEST_API_TOKEN", "--config", "central", "--node", "accounts"]
        if options:
            argv.extend(options)
        argv.extend(command)
        replies = iter([reply(acknowledgement())] if responses is None else responses)
        class FailingOutput(io.StringIO):
            def write(self, text):
                raise BrokenPipeError("PRIVATE_PASSWORD_SENTINEL")

        output, diagnostic = FailingOutput() if output_failure else io.StringIO(), io.StringIO()
        input_stream = io.TextIOWrapper(io.BytesIO(stdin), encoding="utf-8")

        def transport(*args, **kwargs):
            if error is not None:
                raise error
            response = copy.deepcopy(next(replies))
            if isinstance(response, dict):
                response.setdefault("id", args[2]["id"])
            return response

        with (patch.dict(os.environ, WW_TEST_API_TOKEN=API_TOKEN), patch.object(sys, "stdout", output),
              patch.object(sys, "stderr", diagnostic), patch.object(sys, "stdin", input_stream),
              patch.object(input_stream, "isatty", return_value=tty),
              patch.object(CLIENT, "getpass", side_effect=prompts or [PASSWORD, PASSWORD]) as prompt,
              patch.object(CLIENT, "call", side_effect=transport) as call):
            try:
                result = CLIENT.main(argv)
            except SystemExit as exc:
                result = exc.code
        text, errors = output.getvalue(), diagnostic.getvalue()
        self.assertNotIn(PASSWORD, text + errors)
        self.assertNotIn("PRIVATE_PASSWORD_SENTINEL", text + errors)
        self.assertNotIn(API_TOKEN, text + errors)
        return result, text, errors, call, prompt

    def request(self, call, index=0):
        envelope = call.call_args_list[index].args[2]
        self.assertEqual(envelope["auth"], {"client": "admin", "token": API_TOKEN})
        self.assertEqual(envelope["selector"], {"config": "central", "node": "accounts"})
        self.assertEqual(envelope["content_type"], "application/json")
        self.assertEqual(envelope["body_encoding"], "utf8")
        return envelope["operation"], json.loads(envelope["body"])

    def test_audit_health_is_validated_without_exposing_arbitrary_errors(self):
        for error in (None, *sorted(CLIENT.AUDIT_ERRORS)):
            value = status()
            value["audit"].update(enabled=True, healthy=error is None, written_records=MAX_ID,
                                  dropped_records="2", write_failures="1", last_error=error)
            result, text, diagnostic, call, _ = self.invoke(["status"], [reply(value)])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(text)["audit"], value["audit"])
            self.assertEqual(diagnostic, "")
            self.assertEqual(call.call_count, 1)
        for field, bad in (("last_error", "PRIVATE_PASSWORD_SENTINEL"), ("last_error", []),
                           ("written_records", 1), ("dropped_records", "-1"),
                           ("queued_records", "01"), ("healthy", 1), ("enabled", "false")):
            value = status()
            value["audit"][field] = bad
            result, text, diagnostic, call, _ = self.invoke(["status"], [reply(value)])
            self.assertEqual(result, 2)
            self.assertEqual(text, "")
            self.assertEqual(call.call_count, 1)

    def test_read_status_and_exact_large_id(self):
        for command, body, operation, expected in [
                (["status"], status(), "status", {}),
                (["users", "get", LARGE_ID], detail(), "get-user", {"id": LARGE_ID}),
                (["users", "get", MAX_ID], detail(MAX_ID), "get-user", {"id": MAX_ID})]:
            with self.subTest(command=command):
                result, text, errors, call, _ = self.invoke(command, [reply(body)])
                self.assertEqual(result, 0, errors)
                self.assertEqual(json.loads(text), body)
                self.assertEqual(errors, "")
                call.assert_called_once()
                self.assertEqual(self.request(call), (operation, expected))

    def test_create_defaults_and_exact_password_bytes(self):
        result, text, errors, call, prompt = self.invoke(["users", "create", LARGE_ID, "--password-stdin"],
                                                       stdin=PASSWORD.encode("utf-8"))
        self.assertEqual(result, 0, errors)
        self.assertEqual(json.loads(text), acknowledgement())
        call.assert_called_once()
        prompt.assert_not_called()
        operation, body = self.request(call)
        self.assertEqual(operation, "create-user")
        self.assertEqual(body, {"id": LARGE_ID, "password": PASSWORD})

    def test_password_file_preserves_unicode_spaces_and_final_newline(self):
        with tempfile.TemporaryDirectory(prefix="ww-admin-test-") as directory:
            path = Path(directory) / "password"
            path.write_bytes(PASSWORD.encode("utf-8"))
            result, _, errors, call, prompt = self.invoke(
                ["users", "change-password", LARGE_ID, "--if-match", EDIT_TOKEN, "--password-file", str(path)])
            self.assertEqual(result, 0, errors)
            self.assertEqual(self.request(call), ("change-user-password", {
                "id": LARGE_ID, "if_match": EDIT_TOKEN, "password": PASSWORD}))
            call.assert_called_once()
            prompt.assert_not_called()

    def test_password_prompt_requires_matching_hidden_confirmation(self):
        result, _, errors, call, prompt = self.invoke(["users", "create", LARGE_ID], tty=True)
        self.assertEqual(result, 0, errors)
        self.assertEqual(prompt.call_count, 2)
        self.assertEqual(self.request(call)[1]["password"], PASSWORD)
        result, text, errors, call, _ = self.invoke(["users", "create", LARGE_ID], prompts=[PASSWORD, "different"], tty=True)
        self.assertEqual(result, 2)
        self.assertEqual(text, "")
        call.assert_not_called()

    def test_password_prompt_never_falls_back_to_visible_input(self):
        result, text, errors, call, prompt = self.invoke(["users", "create", LARGE_ID])
        self.assertEqual(result, 2)
        self.assertEqual(text, "")
        call.assert_not_called()
        prompt.assert_not_called()
        result, text, errors, call, prompt = self.invoke(
            ["users", "create", LARGE_ID], tty=True, prompts=CLIENT.GetPassWarning("PRIVATE_PASSWORD_SENTINEL"))
        self.assertEqual(result, 2)
        self.assertEqual(text, "")
        self.assertIn("Hidden password", errors)
        call.assert_not_called()
        prompt.assert_called_once()

    def test_sparse_configuration_is_typed_and_not_rounded(self):
        assignments = ["name=Alice = Admin", "email=", "notes=", "wireguard_allowed_ips=10.7.0.1/32",
                       "gid=" + MAX_ID, "enabled=false", "record_stat_interval_ms=2147483647",
                       "limit.traffic.u=0", "limit.traffic.d=1", "limit.traffic.total=" + MAX_ID,
                       "limit.bandwidth.u=2", "limit.bandwidth.d=3", "limit.ips=4", "limit.devices=5",
                       "limit.cons_in=6", "limit.cons_out=7", "time.expire_at_ms=8", "time.expire_after_first_usage_ms=9"]
        command = ["users", "update", LARGE_ID, "--if-match", EDIT_TOKEN]
        for assignment in assignments:
            command.extend(["--set", assignment])
        result, _, errors, call, _ = self.invoke(command)
        self.assertEqual(result, 0, errors)
        operation, body = self.request(call)
        self.assertEqual(operation, "update-user")
        self.assertEqual(body["id"], LARGE_ID)
        self.assertEqual(body["if_match"], EDIT_TOKEN)
        self.assertEqual(body["patch"], {
            "name": "Alice = Admin", "email": "", "notes": "", "wireguard_allowed_ips": "10.7.0.1/32", "gid": MAX_ID,
            "enabled": False, "record_stat_interval_ms": "2147483647",
            "limit": {"traffic": {"u": "0", "d": "1", "total": MAX_ID}, "bandwidth": {"u": "2", "d": "3"},
                      "ips": "4", "devices": "5", "cons_in": "6", "cons_out": "7"},
            "time": {"expire_at_ms": "8", "expire_after_first_usage_ms": "9"}})
        call.assert_called_once()

    def test_create_optional_configuration_uses_same_sparse_schema(self):
        result, _, errors, call, _ = self.invoke(["users", "create", LARGE_ID, "--password-stdin",
                                                "--set", "enabled=false", "--set", "name=Alice"], stdin=b"pass")
        self.assertEqual(result, 0, errors)
        self.assertEqual(self.request(call)[1], {"id": LARGE_ID, "password": "pass",
                                               "config": {"enabled": False, "name": "Alice"}})

    def test_enable_disable_require_and_preserve_operator_edit_token(self):
        for command, enabled in (("enable", True), ("disable", False)):
            result, _, errors, call, _ = self.invoke(["users", command, LARGE_ID, "--if-match", EDIT_TOKEN])
            self.assertEqual(result, 0, errors)
            self.assertEqual(self.request(call), ("update-user", {"id": LARGE_ID, "if_match": EDIT_TOKEN,
                                                                 "patch": {"enabled": enabled}}))
            call.assert_called_once()
            result, _, _, call, _ = self.invoke(["users", command, LARGE_ID])
            self.assertEqual(result, 2)
            call.assert_not_called()

    def test_invalid_patch_and_protected_fields_never_send(self):
        invalid = ["password=PRIVATE_PASSWORD_SENTINEL", "id=2", "usage.u=3", "time.created_at_ms=1",
                   "time.first_usage_at_ms=1", "sha256=x", "limit={}", "enabled=1", "enabled=True",
                   "gid=01", "gid=-1", "gid=+1", "gid= 1", "gid=1.5", "gid=18446744073709551616",
                   "record_stat_interval_ms=2147483648", "name", "name=bad\x00name"]
        for assignment in invalid:
            with self.subTest(assignment=assignment):
                result, text, _, call, _ = self.invoke(
                    ["users", "update", LARGE_ID, "--if-match", EDIT_TOKEN, "--set", assignment])
                self.assertEqual(result, 2)
                self.assertEqual(text, "")
                call.assert_not_called()
        for extra in ([], ["--set", "name=Alice", "--set", "name=Bob"]):
            result, _, _, call, _ = self.invoke(["users", "update", LARGE_ID, "--if-match", EDIT_TOKEN, *extra])
            self.assertEqual(result, 2)
            call.assert_not_called()

    def test_invalid_id_tokens_and_passwords_never_send(self):
        for identifier in ("0", "01", "-1", "1.0", "18446744073709551616"):
            result, _, _, call, _ = self.invoke(["users", "get", identifier])
            self.assertEqual(result, 2)
            call.assert_not_called()
        for token in ("0" * 47, "A" * 48, " " + EDIT_TOKEN, CURSOR1):
            result, _, _, call, _ = self.invoke(["users", "disable", LARGE_ID, "--if-match", token])
            self.assertEqual(result, 2)
            call.assert_not_called()
        for password in (b"", b"a\x00b", b"\xff"):
            result, text, _, call, _ = self.invoke(["users", "create", LARGE_ID, "--password-stdin"], stdin=password)
            self.assertEqual(result, 2)
            self.assertEqual(text, "")
            call.assert_not_called()

    def test_conflicts_and_node_refusals_are_definite_and_never_retried(self):
        for code in ("conflict", "not_found", "credentials_exist", "id_exists", "busy", "timeout", "invalid_request",
                     "invalid_cursor"):
            with self.subTest(code=code):
                result, text, errors, call, _ = self.invoke(
                    ["users", "disable", LARGE_ID, "--if-match", EDIT_TOKEN],
                    [reply({"error": {"code": code}}, 1)])
                self.assertEqual(result, 1)
                self.assertEqual(text, "")
                self.assertIn(code, errors)
                self.assertNotIn("outcome unknown", errors.lower())
                call.assert_called_once()

    def test_local_output_failure_after_acknowledgement_does_not_retry(self):
        result, text, errors, call, _ = self.invoke(
            ["users", "disable", LARGE_ID, "--if-match", EDIT_TOKEN], output_failure=True)
        self.assertEqual(result, 2)
        self.assertEqual(text, "")
        self.assertIn("server accepted the write", errors)
        self.assertNotIn("outcome unknown", errors.lower())
        call.assert_called_once()

    def test_oversized_mutation_and_secret_command_arguments_never_send(self):
        result, _, _, call, _ = self.invoke(
            ["users", "update", LARGE_ID, "--if-match", EDIT_TOKEN, "--set", "notes=" + "a" * 32768])
        self.assertEqual(result, 2)
        call.assert_not_called()
        result, _, _, call, _ = self.invoke(["users", "create", LARGE_ID, "--password-stdin"], stdin=b"a" * 32769)
        self.assertEqual(result, 2)
        call.assert_not_called()
        result, _, _, call, _ = self.invoke(["users", "create", LARGE_ID, "--password", "PRIVATE_PASSWORD_SENTINEL"])
        self.assertEqual(result, 2)
        call.assert_not_called()

    def test_shared_connection_token_boundaries(self):
        result, text, errors, transport, _ = self.invoke(["status"], options=["--token-env", ""])
        self.assertEqual(result, 2)
        self.assertEqual(text, "")
        self.assertNotIn(API_TOKEN, errors)
        transport.assert_not_called()
        with tempfile.TemporaryDirectory(prefix="ww-admin-token-") as directory:
            path = Path(directory) / "token"
            args = CLIENT.parser().parse_args(["--client", "admin", "--node", "accounts", "--token-file", str(path),
                                               "status"])
            for suffix in (b"", b"\r", b"\n", b"\r\n"):
                path.write_bytes(API_TOKEN.encode("ascii") + suffix)
                self.assertEqual(CLIENT.connection_inputs(args), API_TOKEN)
            for data in (b"a" * 67, b"a" * 64 + b"\n\n", b"\xff" * 64, b"a" * 63):
                path.write_bytes(data)
                with self.assertRaises(CLIENT.CommandError) as caught:
                    CLIENT.connection_inputs(args)
                self.assertNotIn(API_TOKEN, str(caught.exception))

    def test_pre_dispatch_gateway_refusals_are_definite(self):
        for code in ("forbidden", "unauthorized", "unsupported_operation", "target_not_found", "ambiguous_target"):
            with self.subTest(code=code):
                result, text, errors, call, _ = self.invoke(
                    ["users", "disable", LARGE_ID, "--if-match", EDIT_TOKEN],
                    [{"error": {"code": code, "message": "PRIVATE_PASSWORD_SENTINEL"}, "result": None}])
                self.assertEqual(result, 2)
                self.assertEqual(text, "")
                self.assertNotIn("outcome unknown", errors.lower())
                call.assert_called_once()

    def test_invalid_handler_response_is_uncertain_for_every_write(self):
        self.assertIn("invalid_response", CLIENT.GATEWAY_ERRORS)
        self.assertNotIn("invalid_response", CLIENT.PRE_DISPATCH_ERRORS)
        for command in (["users", "create", LARGE_ID, "--password-stdin"],
                        ["users", "disable", LARGE_ID, "--if-match", EDIT_TOKEN],
                        ["users", "change-password", LARGE_ID, "--if-match", EDIT_TOKEN, "--password-stdin"]):
            with self.subTest(command=command):
                result, text, errors, call, _ = self.invoke(command,
                    [{"error": {"code": "invalid_response", "message": "PRIVATE_PASSWORD_SENTINEL"}, "result": None}],
                    stdin=PASSWORD.encode("utf-8"))
                self.assertEqual(result, 3)
                self.assertEqual(text, "")
                self.assertIn("Gateway error: invalid_response", errors)
                self.assertIn("outcome unknown", errors.lower())
                call.assert_called_once()

    def test_transport_failures_distinguish_before_send_and_uncertain_writes(self):
        commands = [["users", "create", LARGE_ID, "--password-stdin"],
                    ["users", "update", LARGE_ID, "--if-match", EDIT_TOKEN, "--set", "enabled=false"],
                    ["users", "change-password", LARGE_ID, "--if-match", EDIT_TOKEN, "--password-stdin"]]
        for command in commands:
            for sent in (False, True):
                with self.subTest(command=command, sent=sent):
                    error = CLIENT.ApiTransportError("PRIVATE_PASSWORD_SENTINEL", sent=sent)
                    result, text, errors, call, _ = self.invoke(command, error=error, stdin=PASSWORD.encode("utf-8"))
                    self.assertEqual(result, 3 if sent else 2)
                    self.assertEqual(text, "")
                    self.assertEqual("outcome unknown" in errors.lower(), sent)
                    call.assert_called_once()
        result, _, errors, call, _ = self.invoke(["status"], error=CLIENT.ApiTransportError("failure", sent=True))
        self.assertEqual(result, 2)
        self.assertNotIn("outcome unknown", errors.lower())
        call.assert_called_once()

    def test_invalid_or_late_write_reply_is_uncertain_and_not_printed(self):
        invalid = [None, {"error": {"code": "timeout", "message": "PRIVATE_PASSWORD_SENTINEL"}, "result": None}, reply({}), reply([]),
                   reply(acknowledgement("42")), reply({**acknowledgement(), "config_revision": 84}),
                   reply({**acknowledgement(), "password": "PRIVATE_PASSWORD_SENTINEL"}),
                   reply({"error": {"code": "busy", "password": "PRIVATE_PASSWORD_SENTINEL"}}, 1),
                   reply({"error": {"code": "PRIVATE_PASSWORD_SENTINEL"}}, 1)]
        for response in invalid:
            with self.subTest(response=response):
                result, text, errors, call, _ = self.invoke(
                    ["users", "change-password", LARGE_ID, "--if-match", EDIT_TOKEN, "--password-stdin"],
                    [response], stdin=PASSWORD.encode("utf-8"))
                self.assertEqual(result, 3)
                self.assertEqual(text, "")
                self.assertIn("outcome unknown", errors.lower())
                call.assert_called_once()

    def test_interrupt_during_response_validation_preserves_write_uncertainty(self):
        for command, body, expected in (
                (["users", "disable", LARGE_ID, "--if-match", EDIT_TOKEN], acknowledgement(), 3),
                (["status"], status(), 2)):
            with self.subTest(command=command), patch.object(CLIENT, "strict_json", side_effect=KeyboardInterrupt):
                result, text, errors, call, _ = self.invoke(command, [reply(body)])
                self.assertEqual(result, expected)
                self.assertEqual(text, "")
                self.assertEqual("outcome unknown" in errors.lower(), expected == 3)
                call.assert_called_once()

    def test_unexpected_public_response_fields_are_not_printed(self):
        body = detail()
        body["user"]["password"] = "PRIVATE_PASSWORD_SENTINEL"
        result, text, _, call, _ = self.invoke(["users", "get", LARGE_ID], [reply(body)])
        self.assertEqual(result, 2)
        self.assertEqual(text, "")
        call.assert_called_once()

    def test_list_single_page_and_explicit_cursor(self):
        for command, expected in [(["users", "list"], {"limit": 50}),
                                  (["users", "list", "--limit", "1", "--cursor", CURSOR1], {"limit": 1, "cursor": CURSOR1})]:
            result, text, errors, call, _ = self.invoke(command, [reply(page(cursor=CURSOR2))])
            self.assertEqual(result, 0, errors)
            self.assertEqual(json.loads(text), page(cursor=CURSOR2))
            self.assertEqual(self.request(call), ("list-users", expected))
            call.assert_called_once()

    def test_all_pages_stream_in_order_with_new_correlation_ids(self):
        pages = [page(LARGE_ID, CURSOR1), page("42", CURSOR2), page(MAX_ID)]
        result, text, errors, call, _ = self.invoke(["users", "list", "--all", "--limit", "1"], list(map(reply, pages)))
        self.assertEqual(result, 0, errors)
        self.assertEqual([json.loads(line) for line in text.splitlines()], pages)
        self.assertEqual(call.call_count, 3)
        self.assertEqual([self.request(call, index)[1] for index in range(3)],
                         [{"limit": 1}, {"limit": 1, "cursor": CURSOR1}, {"limit": 1, "cursor": CURSOR2}])
        self.assertEqual(len({invocation.args[2]["id"] for invocation in call.call_args_list}), 3)

    def test_all_pages_stops_on_stale_cursor_without_restarting(self):
        first = page(cursor=CURSOR1)
        result, text, errors, call, _ = self.invoke(
            ["users", "list", "--all"], [reply(first), reply({"error": {"code": "stale_cursor"}}, 1)])
        self.assertEqual(result, 1)
        self.assertEqual([json.loads(line) for line in text.splitlines()], [first])
        self.assertIn("stale_cursor", errors)
        self.assertEqual(call.call_count, 2)
        self.assertEqual(self.request(call, 1)[1]["cursor"], CURSOR1)

    def test_all_pages_bounds_loops_and_maximum_pages(self):
        result, _, errors, call, _ = self.invoke(["users", "list", "--all"],
                                               [reply(page(cursor=CURSOR1)), reply(page("42", CURSOR1))])
        self.assertEqual(result, 2)
        self.assertEqual(call.call_count, 2)
        self.assertTrue("cursor" in errors.lower() or "loop" in errors.lower())
        result, text, errors, call, _ = self.invoke(["users", "list", "--all", "--max-pages", "1"],
                                                  [reply(page(cursor=CURSOR1))])
        self.assertEqual(result, 2)
        call.assert_called_once()
        self.assertEqual(len(text.splitlines()), 1)
        self.assertIn("page", errors.lower())

    def test_invalid_listing_limits_and_cursors_never_send(self):
        for options in (["--limit", "0"], ["--limit", "101"], ["--cursor", EDIT_TOKEN],
                        ["--cursor", "A" * 64], ["--all", "--max-pages", "0"]):
            with self.subTest(options=options):
                result, _, _, call, _ = self.invoke(["users", "list", *options])
                self.assertEqual(result, 2)
                call.assert_not_called()


if __name__ == "__main__":
    unittest.main()
