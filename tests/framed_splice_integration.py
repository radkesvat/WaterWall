#!/usr/bin/env python3
"""HeaderServer and a TCP-connected KeepAlive pair inside the namespace harness."""
import concurrent.futures
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
from httpproxyserver_splice_integration import successful_calls

HOST, APP_PORT, PEER_PORT, BACKEND_PORT = "127.0.0.1", 27981, 27982, 27983


def keepalive_frame(data, kind=1):
    assert len(data) <= 6 * 1024 * 1024
    return (len(data) + 1).to_bytes(4, "big") + bytes([kind]) + data


def keepalive_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        header = exact(sock, 5)
        length, kind = int.from_bytes(header[:4], "big"), header[4]
        assert 1 <= length <= 6 * 1024 * 1024 + 1, "invalid 32-bit KeepAlive length"
        body = exact(sock, length - 1)
        if kind == 1:
            assert len(data) + len(body) <= size, "KeepAlive frame crossed expected payload boundary"
            data += body
        else:
            assert kind in (2, 3) and not body, "unexpected KeepAlive control"
            if kind == 2:
                sock.sendall(keepalive_frame(b"", 3))
    return bytes(data)


def keepalive_eof(sock):
    while first := sock.recv(1):
        header = first + exact(sock, 4)
        assert header[:4] == b"\0\0\0\1" and header[4] in (2, 3), "unexpected trailing application frame"


def listener_node(name, port, next_name):
    return {"name": name, "type": "TcpListener", "next": next_name,
            "settings": {"address": HOST, "port": port, "nodelay": True}}


def connector_node(name, port):
    return {"name": name, "type": "TcpConnector",
            "settings": {"address": HOST, "port": port, "nodelay": True, "fastopen": False}}


def run(binary, mode, enabled):
    tracer = shutil.which("strace")
    if tracer is None:
        raise RuntimeError("strace is required for pipe-to-socket evidence")
    keepalive = mode.startswith("keepalive")
    external_client = mode.startswith("keepalive_client")
    external_server = mode == "keepalive_server"
    watchdog = mode in ("keepalive_client_watchdog", "keepalive_client_timeout")
    timeout = mode == "keepalive_client_timeout"
    client_settings = {"ping-interval": 50}
    if watchdog:
        client_settings.update({"sensitive-mode": True, "tolerance-ms": 250 if timeout else 2000})
    if mode == "keepalive":
        nodes = [listener_node("app", APP_PORT, "client"),
                 {"name": "client", "type": "KeepAliveClient", "next": "carrier",
                  "settings": {"ping-interval": 50}}, connector_node("carrier", PEER_PORT),
                 listener_node("peer", PEER_PORT, "server"),
                 {"name": "server", "type": "KeepAliveServer", "next": "backend"},
                 connector_node("backend", BACKEND_PORT)]
        prefix = b""
    elif keepalive:
        nodes = [listener_node("app", APP_PORT, "framer"),
                 {"name": "framer", "type": "KeepAliveClient" if external_client else "KeepAliveServer",
                  "next": "backend", **({"settings": client_settings} if external_client else {})},
                 connector_node("backend", BACKEND_PORT)]
        prefix = b""
    else:
        override = (BACKEND_PORT if mode == "constant" else "dest_context->port" if mode == "port"
                    else "proxy-protocol->source-fields")
        nodes = [listener_node("app", APP_PORT, "header"),
                 {"name": "header", "type": "HeaderServer", "next": "backend",
                  "settings": {"override": override}}, connector_node("backend", BACKEND_PORT)]
        if mode == "port":
            nodes[-1]["settings"]["port"] = "dest_context->port"
            prefix = BACKEND_PORT.to_bytes(2, "big")
        elif mode == "v1":
            prefix = b"PROXY TCP4 192.0.2.1 198.51.100.1 1234 443\r\n"
        elif mode == "v2":
            prefix = (b"\r\n\r\n\0\r\nQUIT\n\x21\x11\0\x0c" + socket.inet_aton("192.0.2.1") +
                      socket.inet_aton("198.51.100.1") + b"\x04\xd2\x01\xbb")
        else:
            prefix = b""
    data = bytes(range(256)) * (24576 if keepalive else 4096)
    early = data[:8192]
    with tempfile.TemporaryDirectory(prefix="waterwall-framed-splice-") as directory:
        root = Path(directory) / "run"
        root.mkdir()
        (root / "config.json").write_text(json.dumps({"name": "framed-splice", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "configs": ["config.json"],
            "log": {"path": "log/", **{name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                                      for name in ("internal", "core", "network", "dns")}},
            "misc": {"workers": 1, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False, "tcp-tune": False},
        }))
        with socket.socket() as backend, (root / "stdout.log").open("w+") as log:
            backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            backend.bind((HOST, BACKEND_PORT))
            backend.listen()
            backend.settimeout(15)
            process = subprocess.Popen([tracer, "-D", "-f", "-yy", "-e", "trace=splice", "-o",
                                        str(root / "splice.log"), binary], cwd=root,
                                       stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 15
                while True:
                    if process.poll() is not None:
                        raise AssertionError(f"WaterWall startup exited {process.returncode}")
                    try:
                        client = socket.create_connection((HOST, APP_PORT), timeout=1)
                        break
                    except ConnectionRefusedError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(.02)

                if timeout:
                    with client, backend.accept()[0] as conn:
                        conn.settimeout(3)
                        client.settimeout(3)
                        assert exact(conn, 5) == keepalive_frame(b"", 2), "missing watchdog ping"
                        assert conn.recv(1) == b"", "missing pong did not close peer or emitted another ping"
                        assert client.recv(1) == b"", "watchdog did not close application connection"
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=10) == 128 + signal.SIGTERM, "unclean watchdog shutdown"
                    assert "KeepAliveClient: pong timed out" in (root / "stdout.log").read_text(), "missing timeout verdict"
                    return

                def peer():
                    with backend.accept()[0] as conn:
                        conn.settimeout(15)
                        read = keepalive_exact if external_client else exact
                        assert read(conn, len(early)) == early, "early upload changed"
                        conn.sendall(keepalive_frame(early[::-1]) if external_client else early[::-1])
                        assert read(conn, len(data)) == data, "framed upload changed"
                        conn.sendall(keepalive_frame(data[::-1]) if external_client else data[::-1])
                        if watchdog:
                            for _ in range(3):
                                assert exact(conn, 5) == keepalive_frame(b"", 2), "invalid watchdog ping"
                                conn.sendall(keepalive_frame(b"", 3))
                            conn.sendall(keepalive_frame(b"watchdog replies received"))
                        if external_client:
                            keepalive_eof(conn)
                        else:
                            assert conn.recv(1) == b"", "unexpected trailing application bytes"

                with client, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    client.settimeout(15)
                    future = executor.submit(peer)
                    if prefix:
                        client.sendall(prefix[:1])
                    client.sendall(keepalive_frame(early) if external_server else prefix[1:] + early)
                    read = keepalive_exact if external_server else exact
                    assert read(client, len(early)) == early[::-1], "early download changed"
                    client.sendall(keepalive_frame(data) if external_server else data)
                    assert read(client, len(data)) == data[::-1], "framed download changed"
                    if watchdog:
                        assert exact(client, 25) == b"watchdog replies received", "timely pong stopped watchdog pings"
                    client.shutdown(socket.SHUT_RDWR)
                    future.result(timeout=20)
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=10) == 128 + signal.SIGTERM, "unclean framed shutdown"
                calls = list(successful_calls((root / "splice.log").read_text()))
                outputs = set()
                for call in calls:
                    match = re.match(r"splice\(\d+<pipe:\[\d+\]>, NULL, \d+<TCP:\[([^]]+)\]>", call)
                    if match:
                        endpoints = match.group(1)
                        if endpoints.endswith(f"->{HOST}:{BACKEND_PORT}"):
                            outputs.add("up")
                        if endpoints.startswith(f"{HOST}:{APP_PORT}->"):
                            outputs.add("down")
                if enabled:
                    assert outputs == {"up", "down"}, f"missing endpoint splice outputs: {outputs}"
                else:
                    assert not calls, "disabled chain used successful splice I/O"
            except BaseException:
                log.flush()
                print((root / "stdout.log").read_text(), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    run(str(Path(sys.argv[1]).resolve()), sys.argv[2], sys.argv[3] == "true")
    print("Framed TCP integrity, splice policy, keepalive replies and orderly shutdown passed")
