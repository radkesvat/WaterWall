#!/usr/bin/env python3
"""Wait for HTTP CONNECT success before sending the inner Trojan handshake."""
import hashlib
import os
from pathlib import Path
import socket
import struct
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parents[2] / "support" / "python")))
from wwtest.fixtures.http_proxy import header
from wwtest.sockets import exact


def connect_proxy():
    deadline = time.monotonic() + 5
    while True:
        try:
            return socket.create_connection(("127.0.0.1", 29090), timeout=3)
        except ConnectionRefusedError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.05)


with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    listener.settimeout(3)
    port = listener.getsockname()[1]
    with connect_proxy() as client:
        client.sendall(b"CONNECT 127.0.0.1:9 HTTP/1.1\r\nHost: 127.0.0.1:9\r\n\r\n")
        response = header(client)
        assert response.split()[1] == b"200", response

        digest = hashlib.sha224(b"local-trojan-test-password").hexdigest().encode("ascii")
        target = b"\x01\x01" + socket.inet_aton("127.0.0.1") + struct.pack("!H", port)
        payload = b"client payload"
        client.sendall(digest + b"\r\n" + target + b"\r\n" + payload)
        origin, _ = listener.accept()
        with origin:
            origin.settimeout(3)
            assert exact(origin, len(payload)) == payload
            reply = b"origin payload"
            origin.sendall(reply)
            assert exact(client, len(reply)) == reply

print("HTTP CONNECT admitted a Trojan stream before its handshake")
