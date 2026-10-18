#!/usr/bin/env python3
"""Call one explicitly registered WaterWall operation over a reliable TCP stream.

Tokens come from --token-env NAME or --token-file PATH. The client performs no
automatic retries. For TcpOverUdp, connect to a local TcpListener feeding the
production TcpOverUdpClient; this program does not implement its UDP protocol.
"""

import argparse
import base64
import binascii
import json
import math
import os
from pathlib import Path
import re
import socket
import struct
import sys
import uuid


def read_exact(stream, length):
    """Read a complete prefix/body; recv() boundaries are not frame boundaries."""
    chunks = bytearray()
    while len(chunks) < length:
        chunk = stream.recv(length - len(chunks))
        if not chunk:
            raise ValueError("Connection closed before the API frame was complete.")
        chunks.extend(chunk)
    return bytes(chunks)


def call(host, port, envelope, *, timeout=10.0, max_response_bytes=1024 * 1024):
    payload = json.dumps(envelope, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if not 0 < len(payload) <= 0xFFFFFFFF:
        raise ValueError("Request does not fit the API frame length.")
    with socket.create_connection((host, port), timeout=timeout) as stream:
        stream.sendall(struct.pack("!I", len(payload)) + payload)
        length = struct.unpack("!I", read_exact(stream, 4))[0]
        if not 0 < length <= max_response_bytes:
            raise ValueError("Response exceeds the client's envelope limit.")
        response = json.loads(read_exact(stream, length).decode("utf-8"))
    if (not isinstance(response, dict) or response.get("id") != envelope["id"]
            or "error" not in response or "result" not in response):
        raise ValueError("Response has an unexpected request ID or shape.")
    return response


def decode_result(result):
    if not isinstance(result, dict) or not isinstance(result.get("body"), str):
        raise ValueError("Response has an invalid result body.")
    if result.get("body_encoding") == "utf8":
        return result["body"].encode("utf-8")
    if result.get("body_encoding") == "base64":
        try:
            encoded = result["body"].encode("ascii")
            body = base64.b64decode(encoded, validate=True)
        except (UnicodeEncodeError, binascii.Error) as error:
            raise ValueError("Response has invalid base64.") from error
        if base64.b64encode(body) != encoded:
            raise ValueError("Response has noncanonical base64.")
        return body
    raise ValueError("Response has an unsupported body encoding.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9080)
    parser.add_argument("--client", required=True)
    secret = parser.add_mutually_exclusive_group(required=True)
    secret.add_argument("--token-env", metavar="NAME")
    secret.add_argument("--token-file", type=Path, metavar="PATH")
    parser.add_argument("--config", help="Logical configuration name, not a file path")
    parser.add_argument("--node", required=True)
    parser.add_argument("--operation", default="status")
    parser.add_argument("--content-type", default="application/json")
    parser.add_argument("--body-file", type=Path, help="Opaque request bytes; default: {}")
    parser.add_argument("--body-encoding", choices=("utf8", "base64"), default="utf8")
    parser.add_argument("--id", default=None, help="Correlation label; default: random UUID")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--max-response-bytes", type=int, default=1024 * 1024)
    args = parser.parse_args()
    try:
        if not math.isfinite(args.timeout) or args.timeout <= 0 or not 0 < args.max_response_bytes <= 0xFFFFFFFF:
            raise ValueError("Timeout and response limit must be finite positive values.")
        token = (os.environ.get(args.token_env, "") if args.token_env
                 else args.token_file.read_text(encoding="ascii").rstrip("\r\n"))
        if re.fullmatch(r"[0-9a-fA-F]{64}", token) is None:
            raise ValueError("Token input must contain exactly 64 hexadecimal characters.")
        raw_body = args.body_file.read_bytes() if args.body_file else b"{}"
        if args.body_encoding == "utf8":
            body = raw_body.decode("utf-8")
            if "\0" in body:
                raise ValueError("Use base64 for a request body containing NUL.")
        else:
            body = base64.b64encode(raw_body).decode("ascii")
        selector = {"node": args.node}
        if args.config is not None:
            selector["config"] = args.config
        request = {"id": args.id or str(uuid.uuid4()),
                   "auth": {"client": args.client, "token": token},
                   "selector": selector, "operation": args.operation,
                   "content_type": args.content_type,
                   "body_encoding": args.body_encoding, "body": body}
        response = call(args.host, args.port, request, timeout=args.timeout,
                        max_response_bytes=args.max_response_bytes)
        if response.get("error") is not None:
            error = response["error"]
            if not isinstance(error, dict) or not isinstance(error.get("code"), str):
                raise ValueError("Response has an invalid gateway error.")
            print("Gateway error: " + str(error.get("code", "invalid_response")), file=sys.stderr)
            return 2
        result = response.get("result")
        sys.stdout.buffer.write(decode_result(result))
        return 0 if result.get("code") == 0 else 1
    except (OSError, ValueError) as error:
        # Do not print the request, credential, or exception's input values.
        print("API call failed (" + type(error).__name__ + ").", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
