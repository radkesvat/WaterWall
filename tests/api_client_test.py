#!/usr/bin/env python3
"""Example-client conditional-write outcomes: one attempt, explicit recovery, no secrets.

Uses the real CLI adapter with a deterministic transport seam; no network or retries.
CTest: waterwall.api_example_client (production support lane).
"""
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "waterwall_example_api_client", Path(__file__).resolve().parents[1] / "examples/api_client.py")
CLIENT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CLIENT)


class ClientOutcomeTest(unittest.TestCase):
    def invoke(self, response=None, error=None, operation="change-user-password"):
        with tempfile.TemporaryDirectory(prefix="ww-api-client-") as directory:
            body_path = Path(directory) / "request.json"
            body_path.write_text(json.dumps({"id": "42", "if_match": "0" * 48,
                                             "password": "PRIVATE_PASSWORD_SENTINEL"}), encoding="utf-8")
            argv = ["api_client.py", "--client", "password-admin", "--token-env", "WW_TEST_API_TOKEN",
                    "--node", "accounts", "--operation", operation, "--body-file", str(body_path)]
            output = io.BytesIO()
            stdout = io.TextIOWrapper(output, encoding="utf-8")
            stderr = io.StringIO()
            with (patch.object(sys, "argv", argv), patch.object(sys, "stdout", stdout),
                  patch.object(sys, "stderr", stderr), patch.dict(os.environ, WW_TEST_API_TOKEN="a" * 64),
                  patch.object(CLIENT, "call", return_value=response, side_effect=error) as transport):
                result = CLIENT.main()
            stdout.flush()
            text = output.getvalue().decode("utf-8")
            diagnostic = stderr.getvalue()
            transport.assert_called_once()
            self.assertIn("PRIVATE_PASSWORD_SENTINEL", transport.call_args.args[2]["body"])
            self.assertNotIn("PRIVATE_PASSWORD_SENTINEL", text + diagnostic)
            self.assertNotIn("a" * 64, text + diagnostic)
            return result, text, diagnostic

    @staticmethod
    def reply(code, body):
        return {"error": None, "result": {"code": code, "body_encoding": "utf8", "body": json.dumps(body)}}

    def test_success_and_conflict(self):
        acknowledgement = {"id": "42", "config_revision": "87", "edit_token": "0" * 48}
        result, text, diagnostic = self.invoke(self.reply(0, acknowledgement))
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(text), acknowledgement)
        self.assertEqual(diagnostic, "")
        result, text, diagnostic = self.invoke(self.reply(1, {"error": {"code": "conflict"}}))
        self.assertEqual(result, 1)
        self.assertIn("Conflict: read the account again", diagnostic)
        self.assertNotIn("outcome unknown", diagnostic)

    def test_pre_dispatch_and_node_failures_are_definite(self):
        for code in sorted(CLIENT.PRE_DISPATCH_ERRORS):
            with self.subTest(code=code):
                result, _, diagnostic = self.invoke({"error": {"code": code}, "result": None})
                self.assertEqual(result, 2)
                self.assertNotIn("outcome unknown", diagnostic)
        for code in ("invalid_request", "credentials_exist", "busy", "timeout", "password_change_failed"):
            with self.subTest(code=code):
                result, _, diagnostic = self.invoke(self.reply(1, {"error": {"code": code}}))
                self.assertEqual(result, 1)
                self.assertNotIn("outcome unknown", diagnostic)

    def test_unknown_delivery_and_invalid_reply_require_explicit_decision(self):
        invalid = [None, {"error": {"code": "timeout"}}, {"error": None, "result": None},
                   self.reply(0, {}), self.reply(0, []), self.reply(1, {}), self.reply(None, {}),
                   self.reply(1, {"error": {"code": "busy"}, "password": "PRIVATE_PASSWORD_SENTINEL"}),
                   self.reply(1, {"error": {"code": "busy", "password": "PRIVATE_PASSWORD_SENTINEL"}})]
        for response in invalid:
            with self.subTest(response=response):
                result, text, diagnostic = self.invoke(response)
                self.assertEqual(result, 2)
                self.assertEqual(text, "")
                self.assertIn("Password-change outcome unknown", diagnostic)
                self.assertIn("public reads cannot prove which password", diagnostic)
                self.assertIn("Explicitly decide whether to resubmit", diagnostic)
        for error in (OSError("PRIVATE_PASSWORD_SENTINEL"), ValueError("PRIVATE_PASSWORD_SENTINEL")):
            result, text, diagnostic = self.invoke(error=error)
            self.assertEqual(result, 2)
            self.assertEqual(text, "")
            self.assertIn("Password-change outcome unknown", diagnostic)

    def test_update_recovery_still_requires_a_read(self):
        result, _, diagnostic = self.invoke(error=OSError(), operation="update-user")
        self.assertEqual(result, 2)
        self.assertIn("Update outcome unknown", diagnostic)
        self.assertIn("before deciding whether to submit another patch", diagnostic)


if __name__ == "__main__":
    unittest.main()
