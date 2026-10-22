#!/usr/bin/env python3
"""Real authenticated UDP admission retains one distinct-IP reservation per source.

Two sessions from 127.0.0.2 must relay, while 127.0.0.3 cannot reach the target
until both earlier sessions close. Each protocol has its own limit.ips=1 account.
The existing probe runner owns runtime startup, private files and orderly drain.
CTest: waterwall.{trojan,vless,socks5}server_udp_distinct_ip_probe.
"""

from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import socket
import sys
import time
import uuid

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parents[2] / "support/python")))
from wwtest.sockets import exact


HOST = "127.0.0.1"
SOURCE_A, SOURCE_B = "127.0.0.2", "127.0.0.3"
TARGET_PORT = 28423
PORTS = {"trojan": 28420, "vless": 28421, "socks5": 28422}
PASSWORDS = {"trojan": "udp-ip-test", "vless": "42424242-4242-4242-4242-424242424242",
             "socks5": "u:p"}
ADDRESS = b"\x01" + socket.inet_aton(HOST) + TARGET_PORT.to_bytes(2, "big")


class Session:
    """Only the three UDP wire shapes needed by this admission regression."""

    def __init__(self, protocol, source):
        self.protocol = protocol
        self.started = False
        self.response_received = False
        self.udp = None
        self.control = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.control.settimeout(2)
            self.control.bind((source, 0))
            self.control.connect((HOST, PORTS[protocol]))
            if protocol == "socks5":
                self.control.sendall(b"\x05\x01\x02")
                assert exact(self.control, 2) == b"\x05\x02", "SOCKS authentication method refused"
                self.control.sendall(b"\x01\x01u\x01p")
                assert exact(self.control, 2) == b"\x01\x00", "SOCKS credentials refused"
                self.control.sendall(b"\x05\x03\x00\x01" + bytes(6))
                reply = exact(self.control, 10)
                assert reply[:8] == b"\x05\x00\x00\x01" + socket.inet_aton(HOST), "bad dynamic UDP endpoint"
                port = int.from_bytes(reply[8:], "big")
                assert port != 0, "SOCKS did not publish a dynamic UDP endpoint"
                self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.udp.settimeout(2)
                self.udp.bind((source, 0))
                self.udp.connect((HOST, port))
        except BaseException:
            self.close()
            raise

    def send(self, payload):
        if self.protocol == "socks5":
            self.udp.send(b"\x00\x00\x00" + ADDRESS + payload)
            return
        if self.protocol == "trojan":
            packet = ADDRESS + len(payload).to_bytes(2, "big") + b"\r\n" + payload
            header = hashlib.sha224(PASSWORDS["trojan"].encode()).hexdigest().encode()
            header += b"\r\n\x03\x01" + bytes(6) + b"\r\n"
        else:
            packet = len(payload).to_bytes(2, "big") + payload
            header = b"\x00" + uuid.UUID(PASSWORDS["vless"]).bytes
            header += b"\x00\x02" + TARGET_PORT.to_bytes(2, "big") + b"\x01" + socket.inet_aton(HOST)
        self.control.sendall((header if not self.started else b"") + packet)
        self.started = True

    def receive(self, expected):
        if self.protocol == "socks5":
            assert self.udp.recv(65535) == b"\x00\x00\x00" + ADDRESS + expected, "SOCKS UDP reply changed"
        elif self.protocol == "trojan":
            assert exact(self.control, 7) == ADDRESS, "Trojan UDP reply target changed"
            length = int.from_bytes(exact(self.control, 2), "big")
            assert exact(self.control, 2) == b"\r\n", "Trojan UDP reply delimiter changed"
            assert exact(self.control, length) == expected, "Trojan UDP reply changed"
        else:
            if not self.response_received:
                assert exact(self.control, 2) == b"\x00\x00", "VLESS response missing"
                self.response_received = True
            length = int.from_bytes(exact(self.control, 2), "big")
            assert exact(self.control, length) == expected, "VLESS UDP reply changed"

    def finish(self):
        # Observe the carrier owner closing after our EOF before testing the
        # surviving reservation. A local close alone could race the next attempt.
        self.control.shutdown(socket.SHUT_WR)
        assert self.control.recv(1) == b"", f"{self.protocol}: carrier did not settle after EOF"
        self.close()

    def close(self):
        if self.udp is not None:
            self.udp.close()
        self.control.close()


def roundtrip(target, session, payload):
    session.send(payload)
    data, remote = target.recvfrom(65535)
    assert data == payload, f"unexpected target delivery: {data!r}, expected {payload!r}"
    target.sendto(data, remote)
    session.receive(payload)


def must_not_deliver(target, protocol, payload):
    """A transport refusal may look different; the target must see no UDP bytes."""
    session = Session(protocol, SOURCE_B)
    try:
        try:
            session.send(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass
        target.settimeout(.3)
        try:
            data, _ = target.recvfrom(65535)
        except socket.timeout:
            return
        raise AssertionError(f"{protocol}: distinct source B reached the UDP target: {data!r}")
    finally:
        session.close()
        target.settimeout(2)


def released_source_can_forward(target, protocol):
    deadline = time.monotonic() + 5
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        payload = f"{protocol}-B-after-release-{attempt}".encode()
        session = Session(protocol, SOURCE_B)
        try:
            try:
                session.send(payload)
            except (BrokenPipeError, ConnectionResetError):
                pass
            target.settimeout(.15)
            try:
                data, remote = target.recvfrom(65535)
            except socket.timeout:
                continue
            # A delayed rejected packet is also a failure, even across a close.
            assert data == payload, f"{protocol}: stale or rejected UDP target delivery: {data!r}"
            target.sendto(data, remote)
            session.receive(payload)
            return
        finally:
            session.close()
            target.settimeout(2)
    raise AssertionError(f"{protocol}: source B did not forward after all source A sessions closed")


def check_protocol(protocol):
    with ExitStack() as cleanup:
        target = cleanup.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        target.bind((HOST, TARGET_PORT))
        target.settimeout(2)
        first = Session(protocol, SOURCE_A)
        cleanup.callback(first.close)
        second = Session(protocol, SOURCE_A)
        cleanup.callback(second.close)
        roundtrip(target, first, f"{protocol}-A-first".encode())
        roundtrip(target, second, f"{protocol}-A-second".encode())
        must_not_deliver(target, protocol, f"{protocol}-B-both-active".encode())

        first.finish()
        roundtrip(target, second, f"{protocol}-A-still-active".encode())
        must_not_deliver(target, protocol, f"{protocol}-B-one-active".encode())
        # This positive delivery also rejects a delayed B packet from the prior check.
        roundtrip(target, second, f"{protocol}-A-before-close".encode())
        second.finish()
        released_source_can_forward(target, protocol)
    print(f"{protocol}: same-source sharing, distinct-source refusal and final release passed", flush=True)


def main():
    # Initial table publication is the admission readiness event, bounded by the
    # same startup deadline as the probe runner. No readiness UDP backend is created.
    deadline = time.monotonic() + 10
    log = Path("stdout.log")
    while not log.exists() or "AuthenticationClient: pulled 3 users" not in log.read_text():
        assert time.monotonic() < deadline, "initial authentication synchronization did not finish"
        time.sleep(.02)
    selected = os.environ.get("WATERWALL_AUTH_UDP_PROTOCOL")
    assert selected is None or selected in PORTS, "unknown UDP admission protocol"
    for protocol in (selected,) if selected else PORTS:
        check_protocol(protocol)


if __name__ == "__main__":
    main()
