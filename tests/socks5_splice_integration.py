#!/usr/bin/env python3
"""Client/server authentication, CONNECT and UDP association/relay framing with fixed socket peers.
Checks exact response bytes, target endpoints, real positive splice and shutdown143 in both modes;
requires strace and network namespaces. UDP admission never uses a readiness datagram. CTest:
waterwall.socks5client_tcp_auth_splice_false, waterwall.socks5client_tcp_auth_splice_true,
waterwall.socks5client_tcp_noauth_splice_false, waterwall.socks5client_tcp_noauth_splice_true,
waterwall.socks5client_udp_ordinary_reads, waterwall.socks5server_tcp_auth_splice_false,
waterwall.socks5server_tcp_auth_splice_true, waterwall.socks5server_tcp_noauth_splice_false,
waterwall.socks5server_tcp_noauth_splice_true, waterwall.socks5server_udp_ordinary_reads."""
import concurrent.futures
import json
from pathlib import Path
import re
import shutil
import signal
import socket
import sys
import os
import threading
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.config import core_config
from wwtest.run_directory import RunDirectory
from wwtest.process import Process, close_on_error, install_termination_handler

from wwtest.sockets import exact
from wwtest.trace import successful_calls

HOST, LISTEN_PORT, PEER_PORT = "127.0.0.1", 27961, 27962
REPLY = b"\x05\x00\x00\x01" + bytes(6)
CREDENTIALS = b"\x01\x01u\x01p"


def udp_roundtrip(backend, is_client, control):
    payloads = (b"first", bytes(range(256)) * 8, b"")
    envelope = b"\x00\x00\x00\x01" + socket.inet_aton(HOST)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as application:
        application.settimeout(15)
        if is_client:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as relay:
                relay.bind((HOST, PEER_PORT + 1))
                relay.settimeout(15)
                application.sendto(payloads[0], (HOST, LISTEN_PORT))
                with backend.accept()[0] as proxy:
                    proxy.settimeout(15)
                    assert exact(proxy, 3) == b"\x05\x01\x00", "invalid UDP greeting"
                    proxy.sendall(b"\x05\x00")
                    assert exact(proxy, 10) == b"\x05\x03\x00\x01" + bytes(6), "wrong ASSOCIATE command"
                    proxy.sendall(b"\x05\x00\x00\x01" + socket.inet_aton(HOST) +
                                  (PEER_PORT + 1).to_bytes(2, "big"))
                    prefix = envelope + b"\x00\x50"
                    for i, payload in enumerate(payloads):
                        if i:
                            application.sendto(payload, (HOST, LISTEN_PORT))
                        wire, source = relay.recvfrom(65535)
                        assert wire == prefix + payload, "UDP client envelope or body changed"
                        relay.sendto(prefix + payload[::-1], source)
                        received, source = application.recvfrom(65535)
                        assert received == payload[::-1] and source == (HOST, LISTEN_PORT), "UDP reply changed"
        else:
            with control:
                control.sendall(b"\x05\x01\x00")
                assert exact(control, 2) == b"\x05\x00", "noauth UDP method rejected"
                control.sendall(b"\x05\x03\x00\x01" + bytes(6))
                reply = exact(control, 10)
                assert reply[:8] == b"\x05\x00\x00\x01" + socket.inet_aton(HOST), "wrong UDP relay reply"
                port = int.from_bytes(reply[8:], "big")
                assert port, "missing dynamic relay port"
                application.connect((HOST, port))
                prefix = envelope + PEER_PORT.to_bytes(2, "big")
                for payload in payloads:
                    application.send(prefix + payload)
                    received, source = backend.recvfrom(65535)
                    assert received == payload, "UDP server decoded body changed"
                    backend.sendto(payload[::-1], source)
                    assert application.recv(65535) == prefix + payload[::-1], "UDP server reply envelope changed"


def run(binary, side, enabled, authenticated):
    tracer = shutil.which("strace")
    if tracer is None:
        raise RuntimeError("strace is required for pipe-to-socket evidence")
    udp = side.startswith("udp_")
    is_client = side.endswith("client")
    selected_method = 2 if authenticated else 0
    settings = ({"address": "origin.test", "port": 80, "protocol": "tcp",
                 "domain-strategy": "resolve-domains-and-use-only-ipv4"} if is_client else
                {"connect": True, "udp": False, "no-auth": True})
    if udp:
        settings = ({"address": HOST, "port": 80, "protocol": "udp"} if is_client else
                    {"connect": False, "udp": True, "no-auth": True, "ipv4": HOST})
    if authenticated:
        if is_client:
            settings.update({"username": "u", "password": "p"})
        else:
            settings = {"connect": True, "udp": False, "auth-client-node-name": "auth-client"}
    # Keep the runtime's parent directory small and controlled as well as its CWD.
    with RunDirectory("waterwall-socks5-splice-") as directory:
        root = Path(directory) / "run"
        root.mkdir()
        nodes = [
            {"name": "listen", "type": ("UdpListener" if is_client else "TcpUdpListener") if udp else "TcpListener",
             "next": "socks",
             "settings": {"address": HOST, "port": LISTEN_PORT, "nodelay": True}},
            {"name": "socks", "type": "Socks5Client" if is_client else "Socks5Server",
             "next": "connect", "settings": settings},
            {"name": "connect", "type": ("TcpUdpConnector" if is_client else "UdpConnector") if udp else "TcpConnector",
             "settings": {"address": HOST if is_client else "dest_context->address",
                          "port": PEER_PORT if is_client else "dest_context->port",
                          "nodelay": True, "fastopen": False}},
        ]
        if authenticated and not is_client:
            fixture = Path(__file__).resolve().parent / "cases/socks5_connect_large_body_probe/config.json"
            nodes = json.loads(fixture.read_text())["nodes"][:2] + nodes
            (root / "users.json").write_text(json.dumps({
                "users": [{"id": 1001, "password": "u:p", "enabled": True}]}))
        if is_client and not udp:
            (root / "hosts").write_text(f"{HOST} origin.test\n")
        (root / "config.json").write_text(json.dumps({"name": "socks5-splice", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "configs": ["config.json"],
            "log": core_config()["log"],
            **({"dns": {"lookups": "f", "hosts-path": str(root / "hosts")}} if is_client and not udp else {}),
            "misc": {"workers": 1, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False, "tcp-tune": False},
        }))
        early_up = bytes(range(256)) * 32
        early_down = early_up[::-1]
        data = bytes(range(256)) * 4096
        staged = threading.Event()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if udp and not is_client else socket.SOCK_STREAM) as backend, \
                (root / "stdout.log").open("w+") as log:
            backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            backend.bind((HOST, PEER_PORT))
            if not (udp and not is_client):
                backend.listen()
            backend.settimeout(15)
            with Process([tracer, '-D', '-f', '-yy', '-e', 'trace=splice', '-o', str(root / 'splice.log'), binary], cwd=root, log=log) as process:
                deadline = time.monotonic() + 15
                if authenticated and not is_client:
                    while "AuthenticationClient: pulled 1 users" not in (root / "stdout.log").read_text():
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise AssertionError("authentication did not become ready")
                        time.sleep(.02)
                client = None
                while udp and is_client and "listening" not in (root / "stdout.log").read_text().lower():
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise AssertionError("UDP listener did not start")
                    time.sleep(.02)
                while not (udp and is_client):
                    if process.poll() is not None:
                        raise AssertionError(f"WaterWall exited during startup: {process.returncode}")
                    try:
                        client = socket.create_connection((HOST, LISTEN_PORT), timeout=1)
                        break
                    except ConnectionRefusedError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(.02)

                if udp:
                    udp_roundtrip(backend, is_client, client)
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=10) == 128 + signal.SIGTERM, "unclean SOCKS UDP shutdown"
                    assert "splice(" not in (root / "splice.log").read_text(), "UDP association attempted splice I/O"
                    return

                def peer():
                    with backend.accept()[0] as conn:
                        conn.settimeout(15)
                        if is_client:
                            version, count = exact(conn, 2)
                            methods = exact(conn, count)
                            assert version == 5 and selected_method in methods, "invalid greeting"
                            conn.sendall(bytes([5, selected_method]))
                            if authenticated:
                                assert exact(conn, len(CREDENTIALS)) == CREDENTIALS, "credentials changed"
                                conn.sendall(b"\x01\x00")
                            command = b"\x05\x01\x00\x01" + socket.inet_aton(HOST) + b"\x00\x50"
                            assert exact(conn, len(command)) == command, "resolved CONNECT destination changed"
                            conn.sendall(REPLY + early_down)
                        assert exact(conn, len(early_up)) == early_up, "early upload changed"
                        if not is_client:
                            conn.sendall(early_down)
                        assert staged.wait(15), "application did not complete setup"
                        assert exact(conn, len(data)) == data, "opaque upload changed"
                        conn.sendall(data[::-1])
                        assert conn.recv(1) == b"", "unexpected trailing bytes"

                with client, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, close_on_error(client):
                    client.settimeout(15)
                    future = executor.submit(peer)
                    if is_client:
                        client.sendall(early_up)
                    else:
                        client.sendall(bytes([5, 1, selected_method]))
                        assert exact(client, 2) == bytes([5, selected_method]), "wrong selected method"
                        if authenticated:
                            client.sendall(CREDENTIALS)
                            assert exact(client, 2) == b"\x01\x00", "authentication failed"
                        command = b"\x05\x01\x00\x01" + socket.inet_aton(HOST) + PEER_PORT.to_bytes(2, "big")
                        client.sendall(command + early_up)
                        assert exact(client, len(REPLY)) == REPLY, "wrong CONNECT reply"
                    assert exact(client, len(early_down)) == early_down, "coalesced setup body changed"
                    boundary = len((root / "splice.log").read_text())
                    staged.set()
                    client.sendall(data)
                    assert exact(client, len(data)) == data[::-1], "opaque download changed"
                    client.shutdown(socket.SHUT_RDWR)
                    future.result(timeout=20)
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=10) == 128 + signal.SIGTERM, "unclean SOCKS shutdown"
                trace = (root / "splice.log").read_text()
                calls = list(successful_calls(trace[boundary:] if enabled else trace))
                outputs = [call for call in calls if re.match(
                    r"splice\(\d+<pipe:\[\d+\]>, NULL, \d+<TCP:", call)]
                if enabled:
                    assert any(f"->127.0.0.1:{PEER_PORT}" in call for call in outputs), "opaque upload did not splice"
                    assert any(f"127.0.0.1:{LISTEN_PORT}->" in call for call in outputs), "opaque download did not splice"
                else:
                    assert not calls, "splice occurred with misc.splice disabled"


if __name__ == "__main__":
    install_termination_handler()
    run(str(Path(sys.argv[1]).resolve()), sys.argv[2], sys.argv[3] == "true", sys.argv[4] == "auth")
    print("SOCKS5 setup, socket roundtrip and splice policy passed")
