"""Run the shipped administration CLI over private loopback; no mutation retries."""

import json
import os
from pathlib import Path
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
import api_server_probe as api


CLI = Path(api.__file__).resolve().parents[1] / "tunnels/APIServer/client/ww_admin.py"
TOKEN = "0123456789abcdef" * 4
MONITOR_TOKEN = "abcdef0123456789" * 4
LARGE_ID = "9007199254740993"
MAX_ID = "18446744073709551615"
PASSWORD = "  CLI_PRIVATE_PASSWORD_SENTINEL_é\n"
ROTATED_PASSWORD = "CLI_ROTATED_PASSWORD_SENTINEL\n"


def command(arguments, *, stdin=None, expected=0, monitor=False, lines=False):
    environment = os.environ.copy()
    environment["WW_TEST_ADMIN_TOKEN"] = MONITOR_TOKEN if monitor else TOKEN
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    result = subprocess.run(
        [sys.executable, str(CLI), "--host", "127.0.0.1", "--port", "29380", "--timeout", "5",
         "--client", "monitor" if monitor else "admin", "--token-env", "WW_TEST_ADMIN_TOKEN",
         "--config", "admin-fixture", "--node", "accounts", *arguments],
        input=stdin, capture_output=True, timeout=8, env=environment)
    stdout, stderr = result.stdout.decode("utf-8"), result.stderr.decode("utf-8")
    api.require(all(secret not in stdout + stderr for secret in
                    (TOKEN, MONITOR_TOKEN, "CLI_PRIVATE_PASSWORD_SENTINEL", "CLI_ROTATED_PASSWORD_SENTINEL",
                     "CLIInitialAlicePassword", "CLIInitialBobPassword")), "CLI printed a credential")
    api.require(result.returncode == expected,
                "CLI command returned an unexpected exit status: " + arguments[0] + " / " + stderr)
    if expected:
        api.require(not stdout, "CLI refusal printed a success body")
        return stderr
    api.require(not stderr, "Successful CLI invocation emitted a diagnostic")
    return [json.loads(line) for line in stdout.splitlines()] if lines else json.loads(stdout)


def main():
    # Keep the successful readiness connection for a real status request.
    with api.connect() as stream, stream.makefile("rb") as reader:
        request = {"id": "ready", "auth": {"client": "admin", "token": TOKEN},
                   "selector": {"config": "admin-fixture", "node": "accounts"}, "operation": "status",
                   "content_type": "application/json", "body_encoding": "utf8", "body": "{}"}
        stream.sendall(api.frame(request))
        response = api.response(reader, "ready")
        api.require(response["error"] is None and response["result"]["code"] == 0, "Fixture status failed")

    initial = command(["status"])
    api.require(initial["user_count"] == "2" and initial["database_dirty"] is False
                and initial["primary_checkpoint_valid"] is False, "Unexpected initial counts/save state")
    first = command(["users", "get", LARGE_ID])
    api.require(first["user"]["id"] == LARGE_ID, "CLI rounded an account ID")
    created = command(["users", "create", MAX_ID, "--password-stdin", "--set", "name=CLI created"],
                      stdin=PASSWORD.encode("utf-8"))
    api.require(created["id"] == MAX_ID, "Creation acknowledgement lost the exact ID")
    current = command(["users", "get", MAX_ID])
    api.require(current["user"]["enabled"] and current["user"]["usage"] == {"u": "0", "d": "0"},
                "Creation defaults changed")
    updated = command(["users", "update", MAX_ID, "--if-match", current["edit_token"],
                       "--set", "limit.traffic.total=" + MAX_ID, "--set", "notes=CLI note"])
    changed = command(["users", "get", MAX_ID])
    api.require(changed["user"]["limit"]["traffic"]["total"] == MAX_ID
                and changed["user"]["notes"] == "CLI note", "Sparse update lost values")
    diagnostic = command(["users", "disable", MAX_ID, "--if-match", current["edit_token"]], expected=1)
    api.require("conflict" in diagnostic, "Old edit token did not produce a conflict")
    disabled = command(["users", "disable", MAX_ID, "--if-match", updated["edit_token"]])
    api.require(command(["users", "get", MAX_ID])["user"]["enabled"] is False, "Disable did not commit")
    enabled = command(["users", "enable", MAX_ID, "--if-match", disabled["edit_token"]])
    api.require(command(["users", "get", MAX_ID])["user"]["enabled"] is True, "Enable did not commit")
    password_file = Path("password-input")
    password_file.write_bytes(ROTATED_PASSWORD.encode("utf-8"))
    rotated = command(["users", "change-password", MAX_ID, "--if-match", enabled["edit_token"],
                       "--password-file", str(password_file)])
    api.require(int(rotated["config_revision"]) == int(enabled["config_revision"]) + 1,
                "Password mutation did not advance revision once")
    pages = command(["users", "list", "--all", "--limit", "1"], lines=True)
    api.require(len(pages) == 3 and pages[-1]["next_cursor"] is None, "CLI pagination did not complete")
    api.require({user["id"] for page in pages for user in page["users"]} == {LARGE_ID, MAX_ID, "42"},
                "CLI traversal omitted or rounded an account")
    diagnostic = command(["users", "create", MAX_ID, "--password-stdin"], stdin=b"unused", expected=1)
    api.require("id_exists" in diagnostic, "Duplicate creation was not refused")
    changed_status = command(["status"])
    api.require(changed_status["database_dirty"] is True and changed_status["primary_checkpoint_valid"] is False,
                "Account writes lost dirty state or claimed a primary save")
    diagnostic = command(["users", "get", LARGE_ID], monitor=True, expected=2)
    api.require("forbidden" in diagnostic, "Operation permission was not enforced")


if __name__ == "__main__":
    main()
