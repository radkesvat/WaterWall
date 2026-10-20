"""Bounded, single-attempt WaterWall API transport using the Python standard library.

The timeout is one monotonic budget for resolution, connection, sending and the
complete response. Python's blocking system DNS lookup cannot be interrupted;
its elapsed time is charged before a connection is attempted. Use an IP address
when that resolver limitation is unsuitable. This module supplies no encryption:
remote endpoints need an authenticated encrypted transport with peer identity verification.
"""

import base64
import binascii
import json
import math
import re
import socket
import struct
import time


DEFAULT_MAX_BYTES = 1024 * 1024
GATEWAY_ERRORS = frozenset({
    "invalid_request", "invalid_encoding", "unauthorized", "forbidden", "target_not_found",
    "ambiguous_target", "unsupported_api", "unsupported_operation", "unsupported_content_type",
    "busy", "timeout", "shutting_down", "response_too_large", "invalid_response",
})


class ApiTransportError(ValueError):
    """Safe diagnostic; sent means the request may have reached the server."""

    def __init__(self, message, *, sent=False):
        super().__init__(message)
        self.sent = sent


def _text(value, limit=None, *, empty=False):
    if not isinstance(value, str) or (not empty and not value) or "\0" in value:
        raise ValueError("Invalid API text field.")
    encoded = value.encode("utf-8")
    if limit is not None and len(encoded) > limit:
        raise ValueError("API text field exceeds its limit.")
    return encoded


def decode_result(result):
    """Decode a result body without interpreting the target node's schema."""
    if not isinstance(result, dict) or not isinstance(result.get("body"), str):
        raise ValueError("Response has an invalid result body.")
    if result.get("body_encoding") == "utf8":
        try:
            return _text(result["body"], empty=True)
        except ValueError:
            raise ValueError("Response has an invalid UTF-8 body.") from None
    if result.get("body_encoding") == "base64":
        try:
            encoded = result["body"].encode("ascii")
            body = base64.b64decode(encoded, validate=True)
        except (UnicodeEncodeError, binascii.Error):
            raise ValueError("Response has invalid base64.") from None
        if base64.b64encode(body) != encoded:
            raise ValueError("Response has noncanonical base64.")
        return body
    raise ValueError("Response has an unsupported body encoding.")


def _request_payload(envelope, limit):
    if not isinstance(envelope, dict) or set(envelope) != {
        "id", "auth", "selector", "operation", "content_type", "body_encoding", "body"
    }:
        raise ValueError("Invalid request envelope.")
    _text(envelope["id"], 64)
    _text(envelope["operation"], 64)
    _text(envelope["content_type"], 128)
    auth = envelope["auth"]
    if not isinstance(auth, dict) or set(auth) != {"client", "token"}:
        raise ValueError("Invalid request authentication.")
    _text(auth["client"], 256)
    if not isinstance(auth["token"], str) or re.fullmatch(r"[0-9a-fA-F]{64}", auth["token"]) is None:
        raise ValueError("Invalid request token.")
    selector = envelope["selector"]
    if not isinstance(selector, dict) or set(selector) not in ({"node"}, {"node", "config"}):
        raise ValueError("Invalid request selector.")
    for value in selector.values():
        _text(value, 256)
    decode_result(envelope)
    payload = json.dumps(envelope, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if not 0 < len(payload) <= limit:
        raise ValueError("Request exceeds the client's envelope limit.")
    return payload


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Response has duplicate JSON keys.")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("Response has a nonfinite JSON number.")


def _response(payload, request_id):
    response = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_object,
                          parse_constant=_reject_constant)
    if not isinstance(response, dict) or set(response) != {"id", "error", "result"}:
        raise ValueError("Response has an unexpected request ID or shape.")
    # A framing refusal can precede ID parsing. This connection carries exactly
    # one request, so a well-formed gateway error may use the protocol's null ID.
    if response["id"] != request_id and not (response["id"] is None and response["error"] is not None):
        raise ValueError("Response has an unexpected request ID or shape.")
    if response["error"] is not None:
        error = response["error"]
        if (response["result"] is not None or not isinstance(error, dict)
                or set(error) != {"code", "message"}):
            raise ValueError("Response has an invalid gateway error.")
        _text(error["code"], 64)
        if error["code"] not in GATEWAY_ERRORS:
            raise ValueError("Response has an unknown gateway error code.")
        _text(error["message"], empty=True)
    else:
        result = response["result"]
        if (not isinstance(result, dict)
                or set(result) != {"code", "content_type", "body_encoding", "body"}
                or type(result["code"]) is not int or result["code"] not in (0, 1)):
            raise ValueError("Response has an invalid node result.")
        _text(result["content_type"], 128)
        decode_result(result)
    return response


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError("The API call deadline expired.")
    return remaining


def read_exact(stream, length, *, deadline=None):
    """Read a complete prefix/body; recv boundaries are not frame boundaries."""
    chunks = bytearray()
    while len(chunks) < length:
        if deadline is not None:
            stream.settimeout(_remaining(deadline))
        chunk = stream.recv(length - len(chunks))
        if not chunk:
            raise ValueError("Connection closed before the API frame was complete.")
        chunks.extend(chunk)
    return bytes(chunks)


def _connect(host, port, deadline):
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    _remaining(deadline)
    for family, kind, protocol, _, address in addresses:
        stream = None
        connected = False
        try:
            stream = socket.socket(family, kind, protocol)
            stream.settimeout(_remaining(deadline))
            stream.connect(address)
            connected = True
            return stream
        except OSError:
            _remaining(deadline)
        finally:
            if stream is not None and not connected:
                stream.close()
    raise OSError("Could not connect to the API endpoint.")


def call(host, port, envelope, *, timeout=10.0, max_response_bytes=DEFAULT_MAX_BYTES,
         max_request_bytes=DEFAULT_MAX_BYTES):
    """Send one frame and validate one reply, with no automatic write retries.

    ApiTransportError.sent is false only when sending definitely never began.
    A true value means the operation may have run, including after an incomplete
    send or malformed response. Gateway and node errors are validated responses;
    their operation-specific meaning belongs to the caller.
    """
    sent = False
    try:
        if (not isinstance(host, str) or not host or "\0" in host
                or type(port) is not int or not 0 < port <= 65535
                or type(timeout) not in (int, float) or not math.isfinite(timeout) or timeout <= 0
                or any(type(limit) is not int or not 0 < limit <= 0xFFFFFFFF
                       for limit in (max_response_bytes, max_request_bytes))):
            raise ValueError("Invalid API connection options.")
        deadline = time.monotonic() + timeout
        payload = _request_payload(envelope, max_request_bytes)
        _remaining(deadline)
        with _connect(host, port, deadline) as stream:
            stream.settimeout(_remaining(deadline))
            sent = True
            stream.sendall(struct.pack("!I", len(payload)) + payload)
            length = struct.unpack("!I", read_exact(stream, 4, deadline=deadline))[0]
            if not 0 < length <= max_response_bytes:
                raise ValueError("Response exceeds the client's envelope limit.")
            response = _response(read_exact(stream, length, deadline=deadline), envelope["id"])
            _remaining(deadline)
            return response
    except (OSError, ValueError, TypeError, OverflowError, RecursionError):
        message = ("API delivery failed or returned an invalid response; the request may have been processed."
                   if sent else "API request could not be sent; check the inputs, endpoint and connection.")
        raise ApiTransportError(message, sent=sent) from None
