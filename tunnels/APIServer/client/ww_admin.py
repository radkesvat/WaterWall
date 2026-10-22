#!/usr/bin/env python3
"""Administer AuthenticationServer through APIServer using Python 3.10+.

Connection options precede the command. Edits require an edit token from a
previous read; writes are never retried automatically. Run `users --help` for
commands and `users update --help` for the editable fields.
"""

from getpass import getpass, GetPassWarning
import json
from pathlib import Path
import re
import sys
import uuid
import warnings

from ww_api import ApiTransportError, GATEWAY_ERRORS, call, decode_result
from ww_api_cli import (PRE_DISPATCH_ERRORS, WRITES, SafeParser, add_connection_arguments,
                        connection_inputs as shared_connection_inputs, strict_json, unknown_outcome)


UINT64_MAX = (1 << 64) - 1
BODY_LIMIT = 32768
NODE_ERRORS = {
    "invalid_request", "conflict", "busy", "not_found", "invalid_cursor", "stale_cursor",
    "invalid_allowed_ips", "name_exists", "allowed_ips_overlap", "resource_limit",
    "response_too_large", "record_too_large", "user_too_large", "invalid_record_encoding", "timeout",
    "revision_exhausted", "id_exists", "credentials_exist", "creation_failed",
    "password_change_failed",
}
AUDIT_ERRORS = {"open", "write", "flush", "rotate", "close", "invalid-file",
                "queue_full", "sequence_exhausted"}
STRING_FIELDS = {"name", "email", "notes", "wireguard_allowed_ips"}
UINT_FIELDS = {
    "gid", "record_stat_interval_ms", "limit.traffic.u", "limit.traffic.d",
    "limit.traffic.total", "limit.bandwidth.u", "limit.bandwidth.d", "limit.ips",
    "limit.devices", "limit.cons_in", "limit.cons_out", "time.expire_at_ms",
    "time.expire_after_first_usage_ms",
}
FIELDS = STRING_FIELDS | UINT_FIELDS | {"enabled"}


class CommandError(Exception):
    """A fixed diagnostic and process exit code; never include secret values."""

    def __init__(self, message, code=2):
        super().__init__(message)
        self.code = code


class InvalidResponse(ValueError):
    pass


def valid_uint(value, minimum=0, maximum=UINT64_MAX):
    return (isinstance(value, str) and len(value) <= 20
            and re.fullmatch(r"0|[1-9][0-9]*", value) is not None
            and minimum <= int(value) <= maximum)


def valid_text(value):
    if not isinstance(value, str) or "\0" in value:
        return False
    try:
        value.encode("utf-8")
        return True
    except UnicodeError:
        return False


def valid_hex(value, length):
    return isinstance(value, str) and re.fullmatch("[0-9a-f]{" + str(length) + "}", value) is not None


def check(value, schema):
    """Validate a permitted public view before writing any peer data to stdout."""
    if isinstance(schema, dict):
        return (isinstance(value, dict) and value.keys() == schema.keys()
                and all(check(value[key], rule) for key, rule in schema.items()))
    if isinstance(schema, list):
        return isinstance(value, list) and all(check(item, schema[0]) for item in value)
    return schema(value)


BOOL = lambda value: type(value) is bool
ID = lambda value: valid_uint(value, minimum=1)
EDIT_TOKEN = lambda value: valid_hex(value, 48)
CURSOR = lambda value: value is None or valid_hex(value, 64)
PAIR = {"u": valid_uint, "d": valid_uint}
TRAFFIC = {**PAIR, "total": valid_uint}
TIME = {"expire_at_ms": valid_uint, "expire_after_first_usage_ms": valid_uint,
        "first_usage_at_ms": valid_uint}
LIMIT = {"traffic": TRAFFIC, "bandwidth": PAIR, "ips": valid_uint,
         "devices": valid_uint, "cons_in": valid_uint, "cons_out": valid_uint}
REVISION = {"config_revision": ID, "stats_revision": ID, "edit_token": EDIT_TOKEN}
SUMMARY = {
    "id": ID, "gid": valid_uint, "enabled": BOOL,
    "name_preview": lambda value: value is None or (valid_text(value) and len(value.encode("utf-8")) <= 256),
    "name_preview_state": lambda value: value in ("complete", "truncated", "invalid_encoding"),
    "traffic_limit": TRAFFIC, "usage": PAIR, "time": TIME,
}
USER = {"id": ID, "gid": valid_uint, "enabled": BOOL,
        **{field: valid_text for field in STRING_FIELDS}, "record_stat_interval_ms": valid_uint,
        "limit": LIMIT, "time": {**TIME, "created_at_ms": valid_uint}, "usage": PAIR}
SCHEMAS = {
    "status": {**REVISION, "database_loaded": BOOL, "database_dirty": BOOL,
               "primary_checkpoint_valid": BOOL, "user_count": valid_uint,
               "configured_producer_count": valid_uint, "session_record_count": valid_uint,
               "primary_save": {
                   "last_result": lambda value: value in ("not_attempted", "success", "failure"),
                   "last_attempt_age_ms": lambda value: value is None or valid_uint(value),
                   "last_success_age_ms": lambda value: value is None or valid_uint(value)},
               "audit": {"enabled": BOOL, "healthy": BOOL, "queued_records": valid_uint,
                         "written_records": valid_uint, "dropped_records": valid_uint,
                         "suppressed_rejections": valid_uint,
                         "write_failures": valid_uint,
                         "last_error": lambda value: value is None or (isinstance(value, str) and value in AUDIT_ERRORS)}},
    "get-user": {**REVISION, "accounting_time_ms": valid_uint, "user": USER},
    "list-users": {**REVISION, "accounting_time_ms": valid_uint, "total_users": valid_uint,
                   "users": [SUMMARY], "next_cursor": CURSOR},
    **{operation: {"id": ID, "config_revision": ID, "edit_token": EDIT_TOKEN} for operation in WRITES},
}


def parser():
    result = SafeParser(description=__doc__)
    add_connection_arguments(result)
    commands = result.add_subparsers(dest="command", required=True)
    commands.add_parser("status", help="Read server status, save telemetry and audit health")
    users = commands.add_parser("users", help="Read and manage accounts")
    actions = users.add_subparsers(dest="action", required=True)
    actions.add_parser("get", help="Read permitted details and an edit token").add_argument("id")
    listing = actions.add_parser("list", help="Read one page, or stream all pages as JSON Lines")
    listing.add_argument("--limit", type=int, default=50, help="Maximum users per page, 1..100")
    listing.add_argument("--cursor", help="Opaque cursor from the previous page")
    listing.add_argument("--all", action="store_true", help="Write one JSON page per line; never restart stale cursors")
    listing.add_argument("--max-pages", type=int, default=100, help="Safety cap for --all, 1..10000 (default: 100)")
    for name in ("create", "update", "enable", "disable", "change-password"):
        command = actions.add_parser(name)
        command.add_argument("id", help="Permanent nonzero unsigned decimal account ID")
        if name != "create":
            command.add_argument("--if-match", required=True, help="48-character edit token from your prior read")
        if name in ("create", "update"):
            command.add_argument("--set", action="append", default=[], metavar="FIELD=VALUE",
                                 help="Repeat for sparse configuration leaves: " + ", ".join(sorted(FIELDS)))
        if name in ("create", "change-password"):
            password = command.add_mutually_exclusive_group()
            password.add_argument("--password-file", type=Path, metavar="PATH",
                                  help="Read exact UTF-8 password bytes, including any newline")
            password.add_argument("--password-stdin", action="store_true",
                                  help="Read exact UTF-8 password bytes from stdin; otherwise prompt without echo")
    return result


def read_limited(path, limit):
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise CommandError("Input file exceeds the permitted size.")
    return data


def connection_inputs(args):
    try:
        return shared_connection_inputs(args, max_response_bytes=64 * 1024 * 1024)
    except ValueError as error:
        raise CommandError(str(error)) from None


def password_input(args):
    if args.password_file is not None:
        password = read_limited(args.password_file, BODY_LIMIT).decode("utf-8")
    elif args.password_stdin:
        stream = getattr(sys.stdin, "buffer", sys.stdin)
        raw = stream.read(BODY_LIMIT + 1)
        password = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    else:
        if not sys.stdin.isatty():
            raise CommandError("A terminal is required for a hidden password prompt; use --password-file or --password-stdin.")
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            try:
                password = getpass("Password: ")
                repeated = getpass("Repeat password: ")
            except GetPassWarning:
                raise CommandError("Hidden password input is unavailable; use --password-file or --password-stdin.") from None
        if password != repeated:
            raise CommandError("Passwords do not match.")
    if not valid_text(password) or not password or len(password.encode("utf-8")) > BODY_LIMIT:
        raise CommandError("Password must be nonempty UTF-8 without NUL and fit the request limit.")
    return password


def configuration(assignments):
    patch = {}
    seen = set()
    for assignment in assignments:
        field, separator, value = assignment.partition("=")
        if not separator or field not in FIELDS or field in seen:
            raise CommandError("Each --set must name one unique editable field; use users update --help for the field list.")
        seen.add(field)
        if field == "enabled":
            if value not in ("true", "false"):
                raise CommandError("The enabled field accepts only true or false.")
            value = value == "true"
        elif field in UINT_FIELDS:
            maximum = (1 << 31) - 1 if field == "record_stat_interval_ms" else UINT64_MAX
            if not valid_uint(value, maximum=maximum):
                raise CommandError("Numeric configuration fields require canonical unsigned decimal values within their range.")
        elif not valid_text(value):
            raise CommandError("Text configuration fields require UTF-8 without NUL.")
        target = patch
        parts = field.split(".")
        for part in parts[:-1]:
            target = target.setdefault(part, {})
        target[parts[-1]] = value
    return patch


def prepare(args):
    if args.command == "status":
        return "status", {}
    if args.action == "list":
        if not 1 <= args.limit <= 100 or not 1 <= args.max_pages <= 10000:
            raise CommandError("Page size must be 1..100 and page cap must be 1..10000.")
        if args.cursor is not None and not valid_hex(args.cursor, 64):
            raise CommandError("A pagination cursor must contain exactly 64 lowercase hexadecimal characters.")
        return "list-users", {"limit": args.limit, **({"cursor": args.cursor} if args.cursor is not None else {})}
    if not valid_uint(args.id, minimum=1):
        raise CommandError("Account ID must be a nonzero canonical unsigned 64-bit decimal string.")
    body = {"id": args.id}
    if args.action == "get":
        return "get-user", body
    if args.action != "create":
        if not valid_hex(args.if_match, 48):
            raise CommandError("Use the 48-character lowercase hexadecimal edit token from a prior read.")
        body["if_match"] = args.if_match
    if args.action in ("create", "update"):
        patch = configuration(getattr(args, "set"))
        if args.action == "update" and not patch:
            raise CommandError("An update requires at least one --set field.")
        if patch:
            body["config" if args.action == "create" else "patch"] = patch
    if args.action in ("enable", "disable"):
        body["patch"] = {"enabled": args.action == "enable"}
    if args.action in ("create", "change-password"):
        body["password"] = password_input(args)
    operation = {"create": "create-user", "change-password": "change-user-password"}.get(args.action, "update-user")
    return operation, body


def perform(args, token, operation, body):
    encoded = json.dumps(body, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    if len(encoded.encode("utf-8")) > (BODY_LIMIT if operation in WRITES else 4096):
        raise CommandError("Request body exceeds this operation's size limit.")
    selector = {"node": args.node}
    if args.config is not None:
        selector["config"] = args.config
    envelope = {"id": str(uuid.uuid4()), "auth": {"client": args.client, "token": token},
                "selector": selector, "operation": operation, "content_type": "application/json",
                "body_encoding": "utf8", "body": encoded}
    try:
        reply = call(args.host, args.port, envelope, timeout=args.timeout,
                     max_response_bytes=args.max_response_bytes)
    except ApiTransportError as error:
        if operation in WRITES and error.sent:
            raise CommandError(unknown_outcome(operation), 3) from None
        raise CommandError("API transport failed before a complete response was received.") from None
    except (OSError, ValueError, KeyboardInterrupt):
        if operation in WRITES:
            raise CommandError(unknown_outcome(operation), 3) from None
        raise CommandError("API request failed or was interrupted; no automatic retry was made.") from None
    try:
        if (not isinstance(reply, dict) or set(reply) != {"id", "error", "result"}
                or reply["id"] not in (None, envelope["id"])):
            raise InvalidResponse()
        error = reply["error"]
        if error is not None:
            if (reply["result"] is not None or not isinstance(error, dict)
                    or set(error) != {"code", "message"} or not isinstance(error["code"], str)
                    or error["code"] not in GATEWAY_ERRORS or not valid_text(error["message"])):
                raise InvalidResponse()
            code = error["code"]
            if operation in WRITES and code not in PRE_DISPATCH_ERRORS:
                raise CommandError("Gateway error: " + code + ". " + unknown_outcome(operation), 3)
            raise CommandError("Gateway error: " + code + ".")
        result = reply["result"]
        if (reply["id"] != envelope["id"] or not isinstance(result, dict)
                or set(result) != {"code", "content_type", "body_encoding", "body"}
                or type(result["code"]) is not int or result["code"] not in (0, 1)
                or result["content_type"] != "application/json" or result["body_encoding"] != "utf8"):
            raise InvalidResponse()
        value = strict_json(decode_result(result))
        if result["code"] == 1:
            if (not check(value, {"error": {"code": lambda code: isinstance(code, str) and code in NODE_ERRORS}})):
                raise InvalidResponse()
            code = value["error"]["code"]
            advice = ""
            if code == "conflict":
                advice = " Read the account again and reconsider the change before using a new edit token."
            elif code == "stale_cursor":
                advice = " Restart the list explicitly; previously emitted pages are an incomplete traversal."
            raise CommandError("Node error: " + code + "." + advice, 1)
        if not check(value, SCHEMAS[operation]):
            raise InvalidResponse()
        if operation in WRITES and value["id"] != body["id"]:
            raise InvalidResponse()
        if operation == "get-user" and value["user"]["id"] != body["id"]:
            raise InvalidResponse()
        if operation == "list-users":
            if len(value["users"]) > body["limit"] or (not value["users"] and value["next_cursor"] is not None):
                raise InvalidResponse()
            for user in value["users"]:
                if (user["name_preview_state"] == "invalid_encoding") != (user["name_preview"] is None):
                    raise InvalidResponse()
        return value
    except (ValueError, RecursionError, UnicodeError, KeyboardInterrupt):
        if operation in WRITES:
            raise CommandError(unknown_outcome(operation), 3) from None
        raise CommandError("Invalid API response; no response body was printed.") from None


def emit(value, compact=False):
    # ASCII escaping keeps control characters and non-ASCII terminal sequences inert.
    text = json.dumps(value, ensure_ascii=True, indent=None if compact else 2,
                      separators=(",", ":") if compact else None)
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def list_all(args, token, body):
    cursors = {body["cursor"]} if "cursor" in body else set()
    user_ids = set()
    configuration_marker = None
    for index in range(args.max_pages):
        try:
            page = perform(args, token, "list-users", body)
            marker = (page["config_revision"], page["edit_token"], page["total_users"])
            if configuration_marker is not None and marker != configuration_marker:
                raise CommandError("List configuration changed; restart the traversal explicitly.")
            configuration_marker = marker
            ids = [user["id"] for user in page["users"]]
            if len(set(ids)) != len(ids) or any(identifier in user_ids for identifier in ids):
                raise CommandError("Invalid repeated account in list traversal.")
            cursor = page["next_cursor"]
            if cursor is not None and cursor in cursors:
                raise CommandError("Invalid repeated pagination cursor.")
            user_ids.update(ids)
            emit(page, compact=True)
            if cursor is None:
                return
            cursors.add(cursor)
            body = {"limit": args.limit, "cursor": cursor}
        except CommandError as error:
            if index:
                raise CommandError(str(error) + " Previously emitted pages are an incomplete traversal.", error.code) from None
            raise
    raise CommandError("Page cap reached; emitted pages are an incomplete traversal. Continue with the last cursor "
                       "or explicitly choose a larger --max-pages value.")


def main(argv=None):
    args = parser().parse_args(argv)
    completed_write = False
    try:
        token = connection_inputs(args)
        operation, body = prepare(args)
        if operation == "list-users" and args.all:
            list_all(args, token, body)
        else:
            value = perform(args, token, operation, body)
            completed_write = operation in WRITES
            emit(value)
        return 0
    except CommandError as error:
        print(str(error), file=sys.stderr)
        return error.code
    except (OSError, UnicodeError):
        print("Local input/output failed." + (" The server accepted the write; inspect it before submitting again."
                                             if completed_write else ""), file=sys.stderr)
        return 2
    except (KeyboardInterrupt, EOFError):
        print("Command interrupted." + (" The server accepted the write; inspect it before submitting again."
                                        if completed_write else ""), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
