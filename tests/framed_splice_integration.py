#!/usr/bin/env python3
"""Header/KeepAlive transforms and SoftIpLimiter/SpeedLimit with real loopback peers.
Checks protocol framing, staged first/ready exchange, exact reverse echo, endpoint splice and
shutdown143; requires strace/network namespaces. KeepAlive heartbeat/EOF decoding remains
protocol-specific. CTest: waterwall.framed_constant_splice_false,
waterwall.framed_constant_splice_true, waterwall.framed_keepalive_client_splice_false,
waterwall.framed_keepalive_client_splice_true,
waterwall.framed_keepalive_client_timeout_splice_false,
waterwall.framed_keepalive_client_timeout_splice_true,
waterwall.framed_keepalive_client_watchdog_splice_false,
waterwall.framed_keepalive_client_watchdog_splice_true,
waterwall.framed_keepalive_server_splice_false, waterwall.framed_keepalive_server_splice_true,
waterwall.framed_keepalive_splice_false, waterwall.framed_keepalive_splice_true,
waterwall.framed_port_splice_false, waterwall.framed_port_splice_true,
waterwall.framed_v1_splice_false, waterwall.framed_v1_splice_true, waterwall.framed_v2_splice_false,
waterwall.framed_v2_splice_true. Limiter variants:
waterwall.framed_softiplimiter_{vless,trojan}_splice_{false,true} and
waterwall.framed_speedlimit_{line,worker,all}_splice_{false,true}; identity replay,
token-limited TCP integrity, pipe-to-pipe splitting and endpoint splice policy.
ConnectionFisher: waterwall.framed_connectionfisher_splice_{false,true}; winner relay and setup retirement."""
import concurrent.futures
import json
from pathlib import Path
import re
import shutil
import signal
import socket
import sys
import os
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.sockets import configure_listener, connect_when_ready
from wwtest.config import core_config
from wwtest.run_directory import RunDirectory
from wwtest.process import Process, close_on_error, install_termination_handler

from wwtest.sockets import exact
from wwtest.trace import successful_calls

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
    softiplimiter = mode.startswith("softiplimiter_")
    speedlimit = mode.startswith("speedlimit_")
    external_client = mode.startswith("keepalive_client")
    external_server = mode == "keepalive_server"
    watchdog = mode in ("keepalive_client_watchdog", "keepalive_client_timeout")
    timeout = mode == "keepalive_client_timeout"
    client_settings = {"ping-interval": 50}
    if watchdog:
        client_settings.update({"sensitive-mode": True, "tolerance-ms": 250 if timeout else 2000})
    if softiplimiter or speedlimit:
        settings = ({"identifier": mode.removeprefix("softiplimiter_"), "simultaneous-user-limit": 1,
                     "tolerance-ms": 30000} if softiplimiter else
                    {"mega-bytes-per-sec": 1, "work-mode": "pause",
                     "limit-mode": {"line": "per-line", "worker": "per-worker", "all": "all-lines"}[
                         mode.removeprefix("speedlimit_")]})
        nodes = [listener_node("app", APP_PORT, "limiter"),
                 {"name": "limiter", "type": "SoftIpLimiter" if softiplimiter else "SpeedLimit",
                  "next": "backend", "settings": settings}, connector_node("backend", BACKEND_PORT)]
        prefix = (b"\0" + bytes(range(16)) if mode == "softiplimiter_vless" else
                  bytes(range(28)).hex().encode() + b"\r\n" if softiplimiter else b"")
    elif mode == "connectionfisher":
        nodes = [listener_node("app", APP_PORT, "client"),
                 {"name": "client", "type": "ConnectionFisherClient", "next": "carrier",
                  "settings": {"simultaneous-tries-perline": 3}}, connector_node("carrier", PEER_PORT),
                 listener_node("peer", PEER_PORT, "server"),
                 {"name": "server", "type": "ConnectionFisherServer", "next": "backend"},
                 connector_node("backend", BACKEND_PORT)]
        prefix = b""
    elif mode == "keepalive":
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
    data = bytes(range(256)) * (24576 if keepalive else 8192 if speedlimit else 4096)
    early = data[:8192]
    with RunDirectory("waterwall-framed-splice-") as directory:
        root = Path(directory) / "run"
        root.mkdir()
        (root / "config.json").write_text(json.dumps({"name": "framed-splice", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "configs": ["config.json"],
            "log": core_config()["log"],
            "misc": {"workers": 1, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False, "tcp-tune": False},
        }))
        with socket.socket() as backend, (root / "stdout.log").open("w+") as log:
            configure_listener(backend, (HOST, BACKEND_PORT), timeout=15)
            with Process([tracer, '-D', '-f', '-yy', '-e', 'trace=splice', '-o', str(root / 'splice.log'), binary], cwd=root, log=log) as process:
                deadline = time.monotonic() + 15
                client = connect_when_ready(process, (HOST, APP_PORT), deadline=deadline,
                    failure=lambda: AssertionError(f'WaterWall startup exited {process.returncode}'), timeout=1, pause=0.02)

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
                        if softiplimiter:
                            assert exact(conn, len(prefix)) == prefix, "identity wire prefix changed"
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

                with client, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, close_on_error(client):
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
                    if speedlimit:
                        assert any(re.match(r"splice\(\d+<pipe:\[\d+\]>, NULL, \d+<pipe:", call)
                                   for call in calls), "throttling never split a private pipe"
                else:
                    assert not calls, "disabled chain used successful splice I/O"


if __name__ == "__main__":
    install_termination_handler()
    run(str(Path(sys.argv[1]).resolve()), sys.argv[2], sys.argv[3] == "true")
    print("Framed TCP integrity, splice policy, keepalive replies and orderly shutdown passed")
