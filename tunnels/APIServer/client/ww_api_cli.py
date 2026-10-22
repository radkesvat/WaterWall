"""Shared command-line inputs and write-delivery advice for WaterWall API tools.

Transport and gateway-envelope validation stay in ww_api; account schemas belong
in ww_admin. These helpers never retry a request or print caller-owned secrets.
"""

import argparse
import math
import os
from pathlib import Path
import re

from ww_api import DEFAULT_MAX_BYTES, strict_json


WRITES = frozenset({"create-user", "update-user", "change-user-password"})
# These fixed gateway refusals precede operation dispatch. Generic clients keep
# unsupported_api/unsupported_operation vocabulary, although the current gateway
# uses forbidden for an operation absent from its prepared allowlist.
PRE_DISPATCH_ERRORS = frozenset({
    "invalid_request", "invalid_encoding", "unauthorized", "forbidden",
    "target_not_found", "ambiguous_target", "unsupported_api",
    "unsupported_operation", "unsupported_content_type", "busy", "shutting_down",
})


class SafeParser(argparse.ArgumentParser):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("allow_abbrev", False)
        super().__init__(*args, **kwargs)

    def error(self, message):
        self.exit(2, "Invalid command arguments; run --help for usage.\n")


def add_connection_arguments(parser):
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9080)
    parser.add_argument("--client", required=True)
    secret = parser.add_mutually_exclusive_group(required=True)
    secret.add_argument("--token-env", metavar="NAME")
    secret.add_argument("--token-file", type=Path, metavar="PATH")
    parser.add_argument("--config", help="Logical configuration name, not a file path")
    parser.add_argument("--node", required=True)
    parser.add_argument("--timeout", type=float, default=10.0, help="Seconds per API request (default: 10)")
    parser.add_argument("--max-response-bytes", type=int, default=DEFAULT_MAX_BYTES)


def load_token(args):
    if args.token_env is not None:
        if not args.token_env:
            raise ValueError("Token environment name must not be empty.")
        token = os.environ.get(args.token_env, "")
    else:
        with args.token_file.open("rb", buffering=0) as source:
            data = source.read(67)
        if len(data) > 66 or data[64:] not in (b"", b"\r", b"\n", b"\r\n"):
            raise ValueError("Token file must contain 64 hexadecimal characters and optional CR/LF.")
        try:
            token = data[:64].decode("ascii")
        except UnicodeError:
            raise ValueError("Token file must contain ASCII hexadecimal characters.") from None
    if len(token) != 64 or re.fullmatch(r"[0-9a-fA-F]{64}", token) is None:
        raise ValueError("API token input must contain exactly 64 hexadecimal characters.")
    return token


def _text(value, limit=None):
    if not isinstance(value, str) or not value or "\0" in value:
        return False
    try:
        encoded = value.encode("utf-8")
        return limit is None or len(encoded) <= limit
    except UnicodeError:
        return False


def connection_inputs(args, *, max_response_bytes=0xFFFFFFFF):
    if not 1 <= args.port <= 65535 or not math.isfinite(args.timeout) or args.timeout <= 0:
        raise ValueError("Port and timeout must be valid positive values.")
    if not 0 < args.max_response_bytes <= max_response_bytes:
        raise ValueError("Response limit exceeds the supported positive byte range.")
    if any(value is not None and not _text(value, 256) for value in (args.client, args.node, args.config)):
        raise ValueError("Client, configuration and node names must contain 1..256 UTF-8 bytes without NUL.")
    if not _text(args.host):
        raise ValueError("Host must be nonempty and contain no NUL.")
    return load_token(args)


def unknown_outcome(operation):
    if operation == "create-user":
        return ("Creation outcome unknown: retain the original ID and inputs, then read that ID before deciding "
                "whether to submit again. Existence alone does not prove this request created the account or "
                "which password is stored. Explicitly decide whether to retry the same ID; do not select a new ID "
                "automatically.")
    if operation == "change-user-password":
        return ("Password-change outcome unknown: read the account again; public reads cannot prove which password "
                "is stored. Explicitly decide whether to resubmit the desired password with the current edit token.")
    return ("Update outcome unknown: read the account again and compare the intended changes before deciding "
            "whether to submit another patch with a current edit token.")
