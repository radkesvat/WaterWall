#!/usr/bin/env python3
"""Native Linux TrojanServer socket peers; run through the namespace harness."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time

sys.dont_write_bytecode = True
from trojanclient_splice_integration import exact


def address(port):
    return b"\x01\x7f\x00\x00\x01" + port.to_bytes(2, "big")


def frame(port, data):
    return address(port) + len(data).to_bytes(2, "big") + b"\r\n" + data


def receive_frame(sock):
    header = exact(sock, 11)
    assert header[:5] == b"\x01\x7f\x00\x00\x01" and header[-2:] == b"\r\n", "bad UDP header"
    return int.from_bytes(header[5:7], "big"), exact(sock, int.from_bytes(header[7:9], "big"))


def run(binary, mode, enabled, fallback_delay=7):
    tracer = shutil.which("strace")
    if tracer is None:
        raise RuntimeError("strace is required to verify actual splice I/O")
    database = mode == "tcp_db"
    udp = mode == "udp"
    local_fallback = mode == "fallback_http"
    fallback = mode == "fallback" or local_fallback
    with tempfile.TemporaryDirectory(prefix="waterwall-trojanserver-splice-") as directory:
        root = Path(directory)
        settings = {"users": [{"username": "alice", "password": "test"}], "connect": True, "udp": True}
        if fallback:
            settings.update({"fallback-node-name": "fallback", "fallback-intentional-delay-ms": fallback_delay,
                             "fallback-intentional-delay-jitter-ms": 1})
        nodes = [
            {"name": "listen", "type": "TcpListener", "next": "trojan",
             "settings": {"address": "127.0.0.1", "port": 27961, "nodelay": True}},
            {"name": "trojan", "type": "TrojanServer", "next": "connect", "settings": settings},
            {"name": "connect", "type": "UdpConnector" if udp else "TcpConnector",
             "settings": {"address": "dest_context->address", "port": "dest_context->port"}},
        ]
        if database:
            settings.pop("users")
            settings["auth-client-node-name"] = "auth-client"
            fixture = Path(__file__).parent / "cases" / "trojan_password_tcp_loopback" / "config.json"
            nodes = json.loads(fixture.read_text())["nodes"][:2] + nodes
            (root / "users.json").write_text(json.dumps({"users": [{"id": 1001, "name": "alice", "password": "test",
                                                                    "enabled": True, "limit": {"connections-out": 1}}]}))
        if local_fallback:
            nodes.extend([
                {"name": "fallback", "type": "HttpProxyServer", "next": "fallback-connect",
                 "settings": {"no-auth": True}},
                {"name": "fallback-connect", "type": "TcpConnector",
                 "settings": {"address": "dest_context->address", "port": "dest_context->port"}},
            ])
        elif fallback:
            nodes.append({"name": "fallback", "type": "TcpConnector",
                          "settings": {"address": "127.0.0.1", "port": 27962, "fastopen": False}})
        (root / "config.json").write_text(json.dumps({"name": "trojan-server-splice", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "log": {"path": "log/", **{name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                                      for name in ("internal", "core", "network", "dns")}},
            "configs": ["config.json"],
            "misc": {"workers": 1, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False},
        }))
        kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
        with socket.socket(socket.AF_INET, kind) as backend, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second:
            backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            backend.bind(("127.0.0.1", 27962)); backend.settimeout(15)
            second.bind(("127.0.0.1", 27963)); second.settimeout(15)
            if not udp:
                backend.listen()
            with (root / "stdout.log").open("w+") as log:
                process = subprocess.Popen([tracer, "-D", "-f", "-e", "trace=splice", "-o", str(root / "splice.log"), binary],
                                           cwd=root, stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        if process.poll() is not None:
                            raise AssertionError(f"startup exited {process.returncode}")
                        try:
                            client = socket.create_connection(("127.0.0.1", 27961), timeout=1)
                            break
                        except ConnectionRefusedError:
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(0.02)
                    with client:
                        client.settimeout(15)
                        if database:
                            while "AuthenticationClient: pulled 1 users" not in (root / "stdout.log").read_text():
                                if process.poll() is not None or time.monotonic() >= deadline:
                                    raise AssertionError("authentication database did not become ready")
                                time.sleep(0.02)
                        header = hashlib.sha224(b"test").hexdigest().encode() + b"\r\n"
                        header += (b"\x03" + b"\x01" + b"\x00" * 6) if udp else b"\x01" + address(27962)
                        header += b"\r\n"
                        if local_fallback:
                            # Local HTTP responses need no outbound connection or Est.
                            # The fallback emits Payload and Finish in one callback.
                            client.sendall(b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n")
                            response = (b"HTTP/1.1 200 OK\r\n"
                                        b"Allow: GET, HEAD, POST, PUT, DELETE, OPTIONS, CONNECT\r\n"
                                        b"Content-Length: 0\r\nConnection: close\r\n\r\n")
                            assert exact(client, len(response)) == response, "local fallback response lost"
                            assert client.recv(1) == b"", "fallback did not finish after its response"
                        elif udp:
                            client.sendall(header)
                            payloads = [b"", b"a", bytes(range(256)) * 32, b"last", b""]
                            for peer, port in [(backend, 27962), (second, 27963)]:
                                for data in payloads:
                                    client.sendall(frame(port, data))
                                    received, origin = peer.recvfrom(9000)
                                    assert received == data, "UDP request boundary or empty datagram changed"
                                    peer.sendto(data[::-1], origin)
                                    assert receive_frame(client) == (port, data[::-1]), "UDP reply framing changed"
                            client.sendall(frame(27962, b"one") + frame(27963, b"two"))
                            for peer in (backend, second):
                                data, origin = peer.recvfrom(9000)
                                peer.sendto(data, origin)
                            assert dict(receive_frame(client) for _ in range(2)) == {27962: b"one", 27963: b"two"}
                        else:
                            data = bytes(range(256)) * 4096
                            # Larger than an ordinary receive pool tier; each batch
                            # stays below fallback's fixed 1 MiB retention limit.
                            probe = b"invalid Trojan probe\r\n" + data[:256 * 1024] if fallback else b""

                            def peer():
                                with backend.accept()[0] as conn:
                                    conn.settimeout(15)
                                    if fallback:
                                        assert exact(conn, len(probe)) == probe, "fallback replay changed inspected bytes"
                                    conn.sendall(b"server-first")
                                    assert exact(conn, len(data)) == data, "upstream TCP body changed"
                                    conn.sendall(data[::-1])
                                    assert conn.recv(1) == b"", "unexpected bytes during shutdown"

                            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                                result = executor.submit(peer)
                                client.sendall(probe if fallback else header)
                                assert exact(client, 12) == b"server-first"
                                if database:
                                    with socket.create_connection(("127.0.0.1", 27961), timeout=5) as rejected:
                                        rejected.settimeout(5)
                                        rejected.sendall(header)
                                        assert rejected.recv(1) == b"", "UserController allowed a second active connection"
                                    assert "UserController: rejected new connection: connection limit reached" in (root / "stdout.log").read_text(), "rejection did not reach UserController"
                                # Bound fallback delay batches without depending on
                                # receive-pool geometry or socket segmentation.
                                if fallback:
                                    for offset in range(0, len(data), 256 * 1024):
                                        client.sendall(data[offset:offset + 256 * 1024])
                                        time.sleep(0.02)
                                else:
                                    client.sendall(data)
                                assert exact(client, len(data)) == data[::-1], "downstream TCP body changed"
                                client.shutdown(socket.SHUT_RDWR)
                                result.result(timeout=20)
                        # UDP keeps both backend lines live until the source owner drains them.
                        process.send_signal(signal.SIGTERM)
                        assert process.wait(timeout=10) == 128 + signal.SIGTERM, "unclean server shutdown"
                        if udp:
                            assert client.recv(1) == b"", "carrier survived server shutdown"
                    trace = (root / "splice.log").read_text()
                    successful = re.findall(r"(?:splice\(.*|<\.\.\. splice resumed>.*)\s= ([1-9][0-9]*)", trace)
                    # HttpProxyServer remains ordinary-only and disables splice for its chain.
                    assert bool(successful) == (enabled and not local_fallback), "server chain used unexpected splice mode"
                except BaseException:
                    log.flush(); print((root / "stdout.log").read_text(), file=sys.stderr)
                    raise
                finally:
                    if process.poll() is None:
                        process.kill(); process.wait()


if __name__ == "__main__":
    for delay in (0, 7) if sys.argv[2] == "fallback_http" else (7,):
        run(str(Path(sys.argv[1]).resolve()), sys.argv[2], sys.argv[3] == "true", delay)
    print("TrojanServer socket integrity, actual splice transfers and orderly shutdown passed")
