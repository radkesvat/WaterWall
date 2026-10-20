#!/usr/bin/env python3
"""Call one explicitly registered WaterWall operation over a reliable TCP stream.

Tokens come from --token-env NAME or --token-file PATH. The client performs no
automatic retries. For TcpOverUdp, connect to a local TcpListener feeding the
production TcpOverUdpClient; this program does not implement its UDP protocol.
For uncertain create-user outcomes, retain the original ID and inputs and read
that ID before deciding; existence alone does not identify its creator.
For update-user or change-user-password, read get-user first and supply its
edit_token as if_match in a body file. A conflict requires reconsideration after
a fresh read. A lost reply or post-dispatch gateway error leaves the outcome
unknown. Redacted reads cannot prove which password is stored; explicitly decide
whether to resubmit the desired password with the freshly read token.
"""

import base64
from pathlib import Path
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "client"))
from ww_api import ApiTransportError, call, decode_result
from ww_api_cli import (PRE_DISPATCH_ERRORS, WRITES, SafeParser, add_connection_arguments,
                        connection_inputs, strict_json, unknown_outcome)


def unknown_write_outcome(operation):
    print(unknown_outcome(operation), file=sys.stderr)


def main():
    parser = SafeParser(description=__doc__)
    add_connection_arguments(parser)
    parser.add_argument("--operation", default="status")
    parser.add_argument("--content-type", default="application/json")
    parser.add_argument("--body-file", type=Path, help="Opaque request bytes; default: {}")
    parser.add_argument("--body-encoding", choices=("utf8", "base64"), default="utf8")
    parser.add_argument("--id", default=None, help="Correlation label; default: random UUID")
    args = parser.parse_args()
    write_attempted = False
    try:
        token = connection_inputs(args)
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
        write_attempted = args.operation in WRITES
        response = call(args.host, args.port, request, timeout=args.timeout,
                        max_response_bytes=args.max_response_bytes)
        if not isinstance(response, dict):
            raise ValueError("Response has an invalid envelope.")
        if response.get("error") is not None:
            error = response["error"]
            if not isinstance(error, dict) or not isinstance(error.get("code"), str):
                raise ValueError("Response has an invalid gateway error.")
            print("Gateway error: " + str(error.get("code", "invalid_response")), file=sys.stderr)
            if write_attempted and error["code"] not in PRE_DISPATCH_ERRORS:
                unknown_write_outcome(args.operation)
            return 2
        result = response.get("result")
        decoded = decode_result(result)
        if type(result.get("code")) is not int or result["code"] not in {0, 1}:
            raise ValueError("Response has an invalid node result code.")
        if write_attempted:
            body = strict_json(decoded)
            if not isinstance(body, dict):
                raise ValueError("Response has an invalid mutation result.")
            node_error = body.get("error") if isinstance(body, dict) else None
            if result["code"] == 0:
                if (set(body) != {"id", "config_revision", "edit_token"}
                        or any(not isinstance(value, str) for value in body.values())):
                    raise ValueError("Response has an invalid mutation acknowledgement.")
            elif (set(body) != {"error"} or not isinstance(node_error, dict)
                  or set(node_error) != {"code"} or not isinstance(node_error.get("code"), str)):
                raise ValueError("Response has an invalid mutation error.")
            elif node_error["code"] == "conflict":
                print("Conflict: read the account again and reconsider the intended changes.", file=sys.stderr)
        sys.stdout.buffer.write(decoded)
        return 0 if result.get("code") == 0 else 1
    except ApiTransportError as error:
        print("API delivery failed after sending began." if error.sent else "API request could not be sent.",
              file=sys.stderr)
        if write_attempted and error.sent:
            unknown_write_outcome(args.operation)
        return 2
    except (OSError, ValueError) as error:
        # Do not print the request, credential, or exception's input values.
        print("API call failed (" + type(error).__name__ + ").", file=sys.stderr)
        if write_attempted:
            unknown_write_outcome(args.operation)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
