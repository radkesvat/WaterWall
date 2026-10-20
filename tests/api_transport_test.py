#!/usr/bin/env python3
"""Deterministic API framing, validation, deadline and delivery-state coverage."""

import base64
import importlib.util
import json
from pathlib import Path
import socket
import struct
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
SPEC = importlib.util.spec_from_file_location(
    "waterwall_api_transport", Path(__file__).resolve().parents[1] / "tunnels/APIServer/client/ww_api.py")
API = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(API)


def request():
    return {"id": "request-1", "auth": {"client": "admin", "token": "a" * 64},
            "selector": {"config": "edge", "node": "accounts"}, "operation": "status",
            "content_type": "application/json", "body_encoding": "utf8", "body": "{}"}


def response():
    return {"id": "request-1", "error": None,
            "result": {"code": 0, "content_type": "application/json", "body_encoding": "utf8", "body": "{}"}}


def frame(value):
    payload = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode("utf-8")
    return struct.pack("!I", len(payload)) + payload


class Stream:
    def __init__(self, data=b"", *, fragment=1, send_error=None, connect_error=None, on_read=None):
        self.data = data
        self.fragment = fragment
        self.send_error = send_error
        self.connect_error = connect_error
        self.on_read = on_read
        self.sent = []
        self.timeouts = []
        self.closed = False
        self.reads = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def close(self):
        self.closed = True

    def settimeout(self, timeout):
        self.timeouts.append(timeout)

    def connect(self, address):
        if self.connect_error:
            raise self.connect_error

    def sendall(self, data):
        self.sent.append(data)
        if self.send_error:
            raise self.send_error

    def recv(self, length):
        self.reads += 1
        if self.on_read:
            self.on_read()
        length = min(length, self.fragment)
        chunk, self.data = self.data[:length], self.data[length:]
        return chunk


class TransportTest(unittest.TestCase):
    addresses = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 9080))]

    def invoke(self, stream, envelope=None, **options):
        with (patch.object(API.socket, "getaddrinfo", return_value=self.addresses),
              patch.object(API.socket, "socket", return_value=stream)):
            return API.call("localhost", 9080, request() if envelope is None else envelope, **options)

    def assert_failed(self, stream, *, sent=True, envelope=None, **options):
        with self.assertRaises(API.ApiTransportError) as caught:
            self.invoke(stream, envelope, **options)
        self.assertEqual(caught.exception.sent, sent)
        self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
        self.assertNotIn("a" * 64, str(caught.exception))
        self.assertLessEqual(len(stream.sent), 1)
        if sent:
            self.assertTrue(stream.closed)

    def test_fragmented_reply_and_encoded_request_length(self):
        envelope = request()
        envelope["body"] = '{"name":"نام"}'
        stream = Stream(frame(response()))
        self.assertEqual(self.invoke(stream, envelope), response())
        self.assertTrue(stream.closed)
        self.assertEqual(len(stream.sent), 1)
        length = struct.unpack("!I", stream.sent[0][:4])[0]
        self.assertEqual(length, len(stream.sent[0]) - 4)
        self.assertEqual(json.loads(stream.sent[0][4:]), envelope)

    def test_gateway_and_node_error_are_returned(self):
        gateway = {"id": "request-1", "error": {"code": "forbidden", "message": "Operation is forbidden."},
                   "result": None}
        node = response()
        node["result"]["code"] = 1
        uncorrelated = {"id": None, "error": {"code": "invalid_request", "message": "Invalid request."},
                        "result": None}
        invalid_response = {"id": "request-1", "error": {"code": "invalid_response", "message": "Invalid output."},
                            "result": None}
        for reply in (gateway, node, uncorrelated, invalid_response):
            with self.subTest(reply=reply):
                self.assertEqual(self.invoke(Stream(frame(reply))), reply)

    def test_zero_oversized_and_truncated_frames(self):
        for data in (struct.pack("!I", 0), struct.pack("!I", 1025), b"\0\0", struct.pack("!I", 8) + b"{}"):
            with self.subTest(data=data):
                self.assert_failed(Stream(data), max_response_bytes=1024)
        stream = Stream(struct.pack("!I", 1025) + b"body-not-read", fragment=4)
        self.assert_failed(stream, max_response_bytes=1024)
        self.assertEqual(stream.reads, 1)

    def test_invalid_outer_json_and_schema(self):
        bad = [b'{"id":"request-1","id":"request-1","error":null,"result":null}',
               b'{"id":"request-1","error":null,"result":NaN}',
               b'{"id":"request-1","error":null,"result":Infinity}', b"\xff", b"{} trailing",
               b"\xef\xbb\xbf{}", b"[" * 1100 + b"]" * 1100,
               b'{"id":"request-1","error":{"code":"busy","code":"busy","message":"x"},"result":null}',
               None, [], {}, {"id": "request-1", "error": None, "result": None}]
        for change in ({"id": "wrong"}, {"id": None}, {"extra": "PRIVATE_SENTINEL"},
                       {"error": {"code": "busy", "message": "PRIVATE_SENTINEL"}},
                       {"error": {}, "result": None},
                       {"error": {"code": True, "message": "x"}, "result": None},
                       {"error": {"code": "PRIVATE_SENTINEL", "message": "x"}, "result": None},
                       {"error": {"code": "busy\nPRIVATE_SENTINEL", "message": "x"}, "result": None},
                       {"error": {"code": "busy", "message": "\0"}, "result": None}):
            bad.append(dict(response(), **change))
        for reply in bad:
            with self.subTest(reply=repr(reply)[:100]):
                self.assert_failed(Stream(frame(reply)))

    def test_invalid_result_metadata_and_encoded_bodies(self):
        changes = [{"code": True}, {"code": 0.0}, {"code": -1}, {"code": 2}, {"body": {}},
                   {"content_type": None}, {"content_type": "x" * 129}, {"content_type": "a\0b"},
                   {"body": "\0"}, {"body": "\ud800"}, {"body_encoding": "other"},
                   {"body_encoding": "base64", "body": "/x=="},
                   {"body_encoding": "base64", "body": "YQ==\n"},
                   {"body_encoding": "base64", "body": "a==="},
                   {"body_encoding": "base64", "body": "نام"}, {"extra": "PRIVATE_SENTINEL"}]
        for change in changes:
            reply = response()
            reply["result"].update(change)
            # ASCII escapes let an invalid surrogate reach the response parser.
            payload = json.dumps(reply).encode("ascii")
            with self.subTest(change=change):
                self.assert_failed(Stream(frame(payload)))
        reply = response()
        del reply["result"]["content_type"]
        self.assert_failed(Stream(frame(reply)))

    def test_canonical_binary_and_empty_bodies(self):
        for body in (b"", b"\0\xff\x80", bytes(range(256))):
            reply = response()
            reply["result"].update(body_encoding="base64", body=base64.b64encode(body).decode("ascii"))
            actual = self.invoke(Stream(frame(reply)))
            self.assertEqual(API.decode_result(actual["result"]), body)
        reply = response()
        reply["result"]["body"] = ""
        self.assertEqual(API.decode_result(self.invoke(Stream(frame(reply)))["result"]), b"")

    def test_invalid_requests_never_connect(self):
        bad = [None, [], {}, dict(request(), id="x" * 65), dict(request(), body="\0"),
               dict(request(), auth={"client": "admin", "token": "PRIVATE_SENTINEL"}),
               dict(request(), selector={"node": "accounts", "extra": "x"}),
               dict(request(), body_encoding="base64", body="/x==")]
        for envelope in bad:
            with self.subTest(envelope=envelope), patch.object(API.socket, "getaddrinfo") as resolver:
                with self.assertRaises(API.ApiTransportError) as caught:
                    API.call("localhost", 9080, envelope)
                self.assertFalse(caught.exception.sent)
                self.assertNotIn("PRIVATE_SENTINEL", str(caught.exception))
                resolver.assert_not_called()
        for options in ({"max_request_bytes": 1}, {"max_request_bytes": True}, {"max_response_bytes": 0},
                        {"timeout": 0}, {"timeout": float("nan")}, {"timeout": float("inf")}, {"timeout": True}):
            with self.subTest(options=options), patch.object(API.socket, "getaddrinfo") as resolver:
                with self.assertRaises(API.ApiTransportError) as caught:
                    API.call("localhost", 9080, request(), **options)
                self.assertFalse(caught.exception.sent)
                resolver.assert_not_called()

    def test_connection_failures_are_unsent_and_send_failure_is_uncertain(self):
        stream = Stream(connect_error=OSError("PRIVATE_SENTINEL"))
        self.assert_failed(stream, sent=False)
        self.assertTrue(stream.closed)
        self.assertEqual(stream.sent, [])
        self.assert_failed(Stream(send_error=OSError("PRIVATE_SENTINEL")))

    def test_multiple_addresses_share_deadline_and_only_send_once(self):
        clock = [0.0]
        first = Stream(connect_error=ConnectionRefusedError())
        second = Stream(frame(response()), fragment=4096)

        def first_connect(address):
            clock[0] = 0.6
            raise ConnectionRefusedError()

        with (patch.object(API.socket, "getaddrinfo", return_value=self.addresses * 2),
              patch.object(API.socket, "socket", side_effect=[first, second]),
              patch.object(first, "connect", side_effect=first_connect),
              patch.object(API.time, "monotonic", side_effect=lambda: clock[0])):
            self.assertEqual(API.call("localhost", 9080, request(), timeout=1.0), response())
        self.assertTrue(first.closed)
        self.assertEqual(first.sent, [])
        self.assertEqual(len(second.sent), 1)
        self.assertEqual(first.timeouts[0], 1.0)
        self.assertAlmostEqual(second.timeouts[0], 0.4)

    def test_slow_fragments_share_one_timeout_budget(self):
        clock = [0.0]

        def advance():
            clock[0] += 0.6

        stream = Stream(frame(response()), on_read=advance)
        with patch.object(API.time, "monotonic", side_effect=lambda: clock[0]):
            self.assert_failed(stream, timeout=1.0)
        self.assertEqual(stream.reads, 2)
        self.assertAlmostEqual(stream.timeouts[-1], 0.4)

    def test_dns_elapsed_time_is_charged_before_connect(self):
        clock = [0.0]

        def resolve(*args, **kwargs):
            clock[0] = 2.0
            return self.addresses

        with (patch.object(API.time, "monotonic", side_effect=lambda: clock[0]),
              patch.object(API.socket, "getaddrinfo", side_effect=resolve),
              patch.object(API.socket, "socket") as constructor):
            with self.assertRaises(API.ApiTransportError) as caught:
                API.call("localhost", 9080, request(), timeout=1.0)
            self.assertFalse(caught.exception.sent)
            constructor.assert_not_called()


if __name__ == "__main__":
    unittest.main()
