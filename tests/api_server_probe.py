"""Real registered status queries for the namespace API compositions.

The case runner supplies the process, private namespace and copied JSON inputs.
Only startup readiness is retried; submitted operations are never retried.
"""

import json
from pathlib import Path
import socket
import struct
import time


TOKEN = "0123456789abcdef" * 4  # Deliberate public fixture credential.
PORT = 29380
MAX_ENVELOPE = 1024 * 1024


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def connect(port=PORT):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            stream = socket.create_connection(("127.0.0.1", port), timeout=0.2)
            stream.settimeout(5)
            return stream
        except OSError:
            time.sleep(0.03)
    raise AssertionError("API listener did not become ready")


def exact(reader, length):
    result = bytearray()
    while len(result) < length:
        chunk = reader.read(length - len(result))
        require(bool(chunk), "Truncated API frame")
        result.extend(chunk)
    return bytes(result)


def request(identifier, *, config="api-primary", accounting=False, client="monitor", token=TOKEN):
    selector = {"node": "auth-client"}
    if config is not None:
        selector["config"] = config
    return {"id": identifier, "auth": {"client": client, "token": token},
            "selector": selector, "operation": "status", "content_type": "application/json",
            "body_encoding": "utf8", "body": json.dumps({"include_accounting": accounting})}


def frame(value):
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return struct.pack("!I", len(payload)) + payload


def response(reader, identifier, max_envelope=MAX_ENVELOPE):
    length = struct.unpack("!I", exact(reader, 4))[0]
    require(0 < length <= max_envelope, "Invalid API response length")
    result = json.loads(exact(reader, length).decode("utf-8"))
    require(result["id"] == identifier, "API responses lost FIFO/request correlation")
    return result


def status(value, *, accounting=False, multiplier=1):
    require(value["error"] is None, "Status query produced a gateway error")
    result = value["result"]
    require(result["code"] == 0, "Status handler rejected a valid request")
    require(result["content_type"] == "application/json", "Incorrect status content type")
    require(result["body_encoding"] == "utf8", "Incorrect status body encoding")
    body = json.loads(result["body"])
    require(isinstance(body, dict), "Status body is not an object")
    require(type(body.get("traffic_multiplier")) in (int, float)
            and body["traffic_multiplier"] == multiplier, "Incorrect numeric traffic multiplier")
    require(isinstance(body.get("can_authenticate"), bool), "Status lacks admission availability")
    require(body.get("accounting_state") == ("available" if accounting else "not_requested"),
            "Incorrect status accounting availability")
    return body


class ChunkedBody:
    """Decode HTTP chunks without waiting for HTTP EOF or the final chunk."""

    def __init__(self, reader):
        self.reader = reader
        self.remaining = 0

    def read(self, length):
        if self.remaining == 0:
            line = self.reader.readline(1025)
            require(line.endswith(b"\r\n") and len(line) <= 1024, "Invalid HTTP chunk header")
            self.remaining = int(line.split(b";", 1)[0], 16)
            require(self.remaining > 0, "HTTP body ended before complete API response")
        chunk = exact(self.reader, min(length, self.remaining))
        self.remaining -= len(chunk)
        if self.remaining == 0:
            require(exact(self.reader, 2) == b"\r\n", "Invalid HTTP chunk ending")
        return chunk


def http_case():
    with connect() as stream, stream.makefile("rb") as reader:
        messages = [request("http-" + str(i), accounting=i == 2) for i in range(3)]
        payload = b"".join(map(frame, messages))
        headers = ("POST /management HTTP/1.1\r\nHost: api.example.test\r\n"
                   "Content-Type: application/octet-stream\r\nContent-Length: "
                   + str(len(payload)) + "\r\n\r\n").encode("ascii")
        stream.sendall(headers + payload[:2])
        stream.sendall(payload[2:])
        require(reader.readline(1025).startswith(b"HTTP/1.1 200 "), "HTTP tunnel rejected request")
        headers = {}
        for _ in range(32):
            line = reader.readline(4097)
            require(len(line) <= 4096 and line.endswith(b"\r\n"), "Invalid HTTP response header")
            if line == b"\r\n":
                break
            key, value = line.rstrip(b"\r\n").split(b":", 1)
            headers[key.lower()] = value.strip().lower()
        else:
            raise AssertionError("Too many HTTP response headers")
        require(headers.get(b"transfer-encoding") == b"chunked", "Expected chunked body tunnel")
        body = ChunkedBody(reader)
        for i, message in enumerate(messages):
            status(response(body, message["id"]), accounting=i == 2)
        # Recognition above depends on the API length, with the HTTP line still open.


def stream_case(multiconfig=False, small_limit=False, multiplier=1):
    with connect() as stream, stream.makefile("rb") as reader:
        # Every interior split point of the API length prefix, then body fragments.
        for split in range(1, 4):
            identifier = "split-" + str(split)
            payload = frame(request(identifier))
            stream.sendall(payload[:split])
            stream.sendall(payload[split:4])
            for start in range(4, len(payload), 17):
                stream.sendall(payload[start:start + 17])
            status(response(reader, identifier), multiplier=multiplier)
        messages = [request("pipeline-" + str(i), accounting=i == 3) for i in range(4)]
        stream.sendall(b"".join(map(frame, messages)))
        for i, message in enumerate(messages):
            status(response(reader, message["id"]), accounting=i == 3, multiplier=multiplier)
        stream.sendall(frame(request("unqualified", config=None)))
        value = response(reader, "unqualified")
        if multiconfig:
            require(value["error"]["code"] == "ambiguous_target", "Node-only selection ignored ambiguity")
            stream.sendall(frame(request("forbidden", config="api-secondary")))
            require(response(reader, "forbidden")["error"]["code"] == "forbidden",
                    "Exact target permission was not enforced")
            stream.sendall(frame(request("qualified")))
            status(response(reader, "qualified"), multiplier=multiplier)
        else:
            status(value, multiplier=multiplier)
    if not multiconfig:
        for client, token in (("monitor", "f" * 64), ("unknown", TOKEN)):
            with connect() as stream, stream.makefile("rb") as reader:
                stream.sendall(frame(request("denied", client=client, token=token)))
                require(response(reader, "denied")["error"]["code"] == "unauthorized",
                        "Credential failures must use the same gateway code")
                require(reader.read(1) == b"", "Invalid authentication did not close the connection")

    if small_limit:
        with connect(29381) as stream, stream.makefile("rb") as reader:
            stream.sendall(frame(request("small-response")))
            value = response(reader, "small-response", 1024)
            require(value["error"]["code"] == "response_too_large",
                    "A valid status exceeding the encoded cap became an empty node error")


def main(case_directory):
    name = Path(case_directory).name
    if name == "api_http_status":
        http_case()
    else:
        stream_case(name == "api_multiconfig_status", name == "api_tcp_status",
                    multiplier=0.5 if name == "api_tcp_status" else 1)
