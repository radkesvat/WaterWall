#!/usr/bin/env python3
"""A name whose DNS answer takes 2 seconds must still connect with the default core DNS settings.
c-ares shortens its wait to 250 ms once a server has answered fast, as a local caching resolver does,
so the default tries decide how long a name not yet in that cache may take. Real runtime with
Socks5Server -> DomainResolver -> TcpConnector, a stub DNS server and an echo service, all on loopback.
CTest: waterwall.dns_slow_answer."""
import json
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.config import core_config
from wwtest.process import Process, install_termination_handler
from wwtest.run_directory import RunDirectory
from wwtest.sockets import connect_when_ready, exact

HOST, LISTEN_PORT, DNS_PORT, SERVICE_PORT = "127.0.0.1", 26730, 26731, 26732
SLOW_ANSWER_SECONDS = 2
# Enough for c-ares to replace timeout-ms with its average of this server's fast answers.
WARM_UP_NAMES = 5


def serve_dns(server):
    """Answer fast-* names at once. Answer every copy of a slow-* query when the first copy's delay
    ends, the way a caching resolver answers all its clients when its upstream lookup finishes."""
    first_seen = {}
    while True:
        try:
            query, peer = server.recvfrom(1500)
        except OSError:
            return
        end = 12
        while query[end]:
            end += query[end] + 1
        name = query[13:end].lower()
        question = query[12:end + 5]
        is_a = question[-4:-2] == b"\x00\x01"
        answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04" + socket.inet_aton(HOST) if is_a else b""
        reply = query[:2] + b"\x81\x80\x00\x01" + struct.pack(">HHH", 1 if is_a else 0, 0, 0) + question + answer
        delay = 0
        if name.startswith(b"slow-"):
            now = time.monotonic()
            delay = max(0, first_seen.setdefault(question, now) + SLOW_ANSWER_SECONDS - now)
        threading.Timer(delay, server.sendto, (reply, peer)).start()


def serve_echo(listener):
    while True:
        try:
            connection = listener.accept()[0]
        except OSError:
            return

        def echo(peer=connection):
            with peer:
                while data := peer.recv(4096):
                    peer.sendall(data)
        threading.Thread(target=echo, daemon=True).start()


def roundtrip(process, name):
    """One byte through the proxy to name; returns the seconds it took."""
    start = time.monotonic()
    with connect_when_ready(process, (HOST, LISTEN_PORT), deadline=start + 10,
                            failure=lambda: AssertionError("WaterWall exited")) as client:
        client.settimeout(15)
        client.sendall(b"\x05\x01\x00")
        assert exact(client, 2) == b"\x05\x00", "SOCKS5 greeting failed"
        host = name.encode()
        client.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack(">H", SERVICE_PORT))
        try:
            assert exact(client, 10)[:2] == b"\x05\x00", f"SOCKS5 CONNECT to {name} refused"
        except AssertionError as error:
            raise AssertionError(f"{name} closed after {time.monotonic() - start:.2f} s: {error}") from error
        client.sendall(b"x")
        assert exact(client, 1) == b"x", "echo mismatch"
    return time.monotonic() - start


def main():
    install_termination_handler()
    with RunDirectory("ww-dns-slow-answer-") as root:
        nodes = [
            {"name": "in", "type": "TcpListener", "settings": {"address": HOST, "port": LISTEN_PORT}, "next": "socks"},
            {"name": "socks", "type": "Socks5Server", "settings": {"no-auth": True, "connect": True}, "next": "resolve"},
            {"name": "resolve", "type": "DomainResolver", "settings": {"strategy": "core-settings"}, "next": "out"},
            {"name": "out", "type": "TcpConnector",
             "settings": {"address": "dest_context->address", "port": "dest_context->port"}},
        ]
        (root / "config.json").write_text(json.dumps({"name": "dns-slow-answer", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            **core_config(),
            # Only the server is set: the timing under test is the defaults'.
            "dns": {"lookups": "b", "servers": [f"{HOST}:{DNS_PORT}"]},
        }))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns, socket.socket() as service:
            dns.bind((HOST, DNS_PORT))
            service.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            service.bind((HOST, SERVICE_PORT))
            service.listen()
            threading.Thread(target=serve_dns, args=(dns,), daemon=True).start()
            threading.Thread(target=serve_echo, args=(service,), daemon=True).start()
            with Process([sys.argv[1]], cwd=root, log_path=root / "stdout.log") as process:
                for index in range(WARM_UP_NAMES):
                    roundtrip(process, f"fast-{index}.test")
                took = roundtrip(process, "slow-0.test")
                assert took >= SLOW_ANSWER_SECONDS, f"the slow answer was not waited for: {took:.2f} s"
                print(f"slow answer connected after {took:.2f} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
