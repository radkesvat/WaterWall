#!/usr/bin/env python3
"""UUID local/database authentication, TCP/fallback replay and UDP target framing; local HTTP fallback
can respond before Est. Fixed loopback peers, exact payload/EOF, positive splice and shutdown143.
Requires strace/network namespaces. CTest: waterwall.vlessserver_fallback_http_splice_false,
waterwall.vlessserver_fallback_http_splice_true, waterwall.vlessserver_fallback_splice_false,
waterwall.vlessserver_fallback_splice_true, waterwall.vlessserver_tcp_db_splice_false,
waterwall.vlessserver_tcp_db_splice_true, waterwall.vlessserver_tcp_splice_false,
waterwall.vlessserver_tcp_splice_true, waterwall.vlessserver_udp_splice_false,
waterwall.vlessserver_udp_splice_true. The tcp_db_bandwidth and udp_db_bandwidth variants
exercise finite UserController rates with exact FIFO/boundary and clean shutdown oracles.
TCP also keeps two same-user sessions live across bandwidth edits with retained input;
controlled-time native tests own rate precision, without wall-clock throughput thresholds."""
import concurrent.futures
import threading
import uuid
import json
from pathlib import Path
import shutil
import signal
import socket
import sys
import os
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.sockets import connect_when_ready
from wwtest.config import core_config
from wwtest.trace import positive_splice_counts
from wwtest.run_directory import RunDirectory
from wwtest.process import Process, close_on_error, install_termination_handler

from wwtest.sockets import exact
import api_server_probe as api


def address(port):
    return port.to_bytes(2, "big") + b"\x01\x7f\x00\x00\x01"


def frame(data):
    return len(data).to_bytes(2, "big") + data


def receive_frame(sock):
    return exact(sock, int.from_bytes(exact(sock, 2), "big"))


def shared_bandwidth_tcp(client, backend, header):
    """Real shared-user streams survive a policy refresh while input is retained."""
    first_prefix = threading.Event()
    payloads = [b"first-prefix" + bytes(range(256)) * 512 + b"first-tail",
                b"second-prefix" + bytes(reversed(range(256))) * 512 + b"second-tail"]

    def peer(conn, expected):
        conn.settimeout(15)
        conn.sendall(b"server-first")
        prefix = exact(conn, 1)
        assert prefix == expected[:1], "shared stream changed its first byte"
        first_prefix.set()  # A one-byte grant proves the larger delivery has entered shaping.
        assert prefix + exact(conn, len(expected) - 1) == expected, "shared stream FIFO changed"
        conn.sendall(expected[::-1])
        assert conn.recv(1) == b"", "unexpected shared-stream shutdown bytes"

    with socket.create_connection(("127.0.0.1", 27961), timeout=5) as second, \
            close_on_error(client), close_on_error(second):
        second.settimeout(15)
        client.sendall(header)
        with backend.accept()[0] as first_remote:
            second.sendall(header)
            with backend.accept()[0] as second_remote, \
                    concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                results = [executor.submit(peer, conn, data)
                           for conn, data in zip((first_remote, second_remote), payloads)]
                streams = (client, second)
                for stream in streams:
                    assert exact(stream, 2) == b"\x00\x00", "missing shared VLESS response"
                    assert exact(stream, 12) == b"server-first", "second same-user session was not admitted"

                with api.connect(27963) as admin, admin.makefile("rb") as reader:
                    sequence = 0

                    def query(node, operation, body):
                        nonlocal sequence
                        sequence += 1
                        identifier = "bandwidth-" + str(sequence)
                        admin.sendall(api.frame({
                            "id": identifier, "auth": {"client": "bandwidth-test", "token": api.TOKEN},
                            "selector": {"config": "vless-server-splice", "node": node},
                            "operation": operation, "content_type": "application/json",
                            "body_encoding": "utf8", "body": json.dumps(body)}))
                        envelope = api.response(reader, identifier)
                        assert envelope["error"] is None and envelope["result"]["code"] == 0, "bandwidth API refusal"
                        return json.loads(envelope["result"]["body"])

                    def change_rate(rate):
                        current = query("auth-db", "get-user", {"id": "1001"})
                        changed = query("auth-db", "update-user", {
                            "id": "1001", "if_match": current["edit_token"],
                            "patch": {"limit": {"bandwidth": {"u": str(rate), "d": str(rate)}}}})
                        deadline = time.monotonic() + 8
                        while True:
                            status = query("auth-client", "status", {})
                            if int(status["applied_config_revision"]) >= int(changed["config_revision"]):
                                assert status["can_authenticate"], "refresh lost cached admission"
                                return
                            assert time.monotonic() < deadline, "bandwidth edit did not reach the live client"
                            time.sleep(.02)

                    change_rate(1)
                    for stream, data in zip(streams, payloads):
                        stream.sendall(data[:31])
                        stream.sendall(data[31:])
                    assert first_prefix.wait(5), "queued shared-user input made no initial progress"
                    # At 1 byte/s these bodies cannot finish within socket deadlines. This
                    # edit must release retained FIFO data on both already-open sessions.
                    change_rate(0)
                    for stream, data in zip(streams, payloads):
                        assert exact(stream, len(data)) == data[::-1], "refreshed shared-user reply changed"
                for stream in streams:
                    stream.shutdown(socket.SHUT_RDWR)
                for result in results:
                    result.result(timeout=20)


def run(binary, mode, enabled, fallback_delay=7):
    tracer = shutil.which("strace")
    if tracer is None:
        raise RuntimeError("strace is required to verify actual splice I/O")
    bandwidth = mode in ("tcp_db_bandwidth", "udp_db_bandwidth")
    database = mode == "tcp_db" or bandwidth
    shared_bandwidth = mode == "tcp_db_bandwidth"
    udp = mode in ("udp", "udp_db_bandwidth")
    local_fallback = mode == "fallback_http"
    fallback = mode == "fallback" or local_fallback
    with RunDirectory("waterwall-vlessserver-splice-") as directory:
        root = Path(directory)
        settings = {"users": [{"username": "alice", "uuid": "42424242-4242-4242-4242-424242424242"}], "connect": True, "udp": True}
        if fallback:
            settings.update({"fallback-node-name": "fallback", "fallback-intentional-delay-ms": fallback_delay,
                             "fallback-intentional-delay-jitter-ms": 1})
        nodes = [
            {"name": "listen", "type": "TcpListener", "next": "vless",
             "settings": {"address": "127.0.0.1", "port": 27961, "nodelay": True}},
            {"name": "vless", "type": "VlessServer", "next": "connect", "settings": settings},
            {"name": "connect", "type": "UdpConnector" if udp else "TcpConnector",
             "settings": {"address": "dest_context->address", "port": "dest_context->port"}},
        ]
        if database:
            settings.pop("users")
            settings["auth-client-node-name"] = "auth-client"
            fixture = Path(__file__).parent / "cases" / "vless_auth_tcp_loopback" / "config.json"
            nodes = json.loads(fixture.read_text())["nodes"][:2] + nodes
            limits = {"connections-out": 2 if shared_bandwidth else 1}
            if bandwidth:
                # Each 8192-byte UDP payload exceeds the 6553-byte ordinary burst.
                limits["bandwidth"] = {"up": 65536, "down": 65536}
            (root / "users.json").write_text(json.dumps({"users": [{"id": 1001, "name": "alice", "password": "42424242-4242-4242-4242-424242424242",
                                                                    "enabled": True, "limit": limits}]}))
        if shared_bandwidth:
            nodes[0]["settings"]["pull-interval-ms"] = 100
            nodes.extend([
                {"name": "bandwidth-api-listener", "type": "TcpListener", "next": "bandwidth-api",
                 "settings": {"address": "127.0.0.1", "port": 27963}},
                {"name": "bandwidth-api", "type": "APIServer", "settings": {"clients": [
                    {"name": "bandwidth-test", "token": api.TOKEN, "allow": [
                        {"config": "vless-server-splice", "node": "auth-db",
                         "operations": ["get-user", "update-user"]},
                        {"config": "vless-server-splice", "node": "auth-client", "operations": ["status"]}]}]}},
            ])
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
        (root / "config.json").write_text(json.dumps({"name": "vless-server-splice", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "log": core_config()["log"],
            "configs": ["config.json"],
            "misc": {"workers": 1, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False},
        }))
        kind = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
        with socket.socket(socket.AF_INET, kind) as backend:
            backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            backend.bind(("127.0.0.1", 27962)); backend.settimeout(15)
            if not udp:
                backend.listen()
            with (root / "stdout.log").open("w+") as log:
                with Process([tracer, '-D', '-f', '-e', 'trace=splice', '-o', str(root / 'splice.log'), binary], cwd=root, log=log) as process:
                    deadline = time.monotonic() + 10
                    client = connect_when_ready(process, ('127.0.0.1', 27961), deadline=deadline,
                        failure=lambda: AssertionError(f'startup exited {process.returncode}'), timeout=1, pause=0.02)
                    with client:
                        client.settimeout(15)
                        if database:
                            while "AuthenticationClient: pulled 1 users" not in (root / "stdout.log").read_text():
                                if process.poll() is not None or time.monotonic() >= deadline:
                                    raise AssertionError("authentication database did not become ready")
                                time.sleep(0.02)
                        header = b"\x00" + uuid.UUID("42424242-4242-4242-4242-424242424242").bytes
                        header += b"\x00" + (b"\x02" if udp else b"\x01") + address(27962)
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
                            for index, data in enumerate(payloads):
                                client.sendall(frame(data))
                                received, origin = backend.recvfrom(9000)
                                assert received == data, "UDP request boundary changed"
                                backend.sendto(data[::-1], origin)
                                if index == 0:
                                    assert exact(client, 2) == b"\x00\x00", "missing VLESS response"
                                assert receive_frame(client) == data[::-1], "UDP reply framing changed"
                            batch = (b"one", b"", b"two", b"")
                            client.sendall(b"".join(frame(data) for data in batch))
                            for expected in batch:
                                data, origin = backend.recvfrom(9000)
                                assert data == expected, "fixed destination UDP order changed"
                                backend.sendto(data, origin)
                                assert receive_frame(client) == expected
                        elif shared_bandwidth:
                            shared_bandwidth_tcp(client, backend, header)
                        else:
                            data = bytes(range(256)) * (512 if bandwidth else 4096)
                            # Larger than an ordinary receive pool tier; each batch
                            # stays below fallback's fixed 2 MiB retention limit.
                            probe = b"invalid VLESS probe\r\n" + data[:256 * 1024] if fallback else b""

                            def peer():
                                with backend.accept()[0] as conn:
                                    conn.settimeout(15)
                                    if fallback:
                                        assert exact(conn, len(probe)) == probe, "fallback replay changed inspected bytes"
                                    conn.sendall(b"server-first")
                                    assert exact(conn, len(data)) == data, "upstream TCP body changed"
                                    conn.sendall(data[::-1])
                                    assert conn.recv(1) == b"", "unexpected bytes during shutdown"

                            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, close_on_error(client):
                                result = executor.submit(peer)
                                client.sendall(probe if fallback else header)
                                if not fallback:
                                    assert exact(client, 2) == b"\x00\x00", "missing VLESS response"
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
                        # UDP keeps the fixed backend line live until the source owner drains them.
                        process.send_signal(signal.SIGTERM)
                        assert process.wait(timeout=10) == 128 + signal.SIGTERM, "unclean server shutdown"
                        if udp:
                            assert client.recv(1) == b"", "carrier survived server shutdown"
                    trace = (root / "splice.log").read_text()
                    successful = positive_splice_counts(trace)
                    # HttpProxyServer materializes its local OPTIONS input on the splice-capable chain.
                    assert bool(successful) == enabled, "server chain used unexpected splice mode"


if __name__ == "__main__":
    install_termination_handler()
    for delay in (0, 7) if sys.argv[2] == "fallback_http" else (7,):
        run(str(Path(sys.argv[1]).resolve()), sys.argv[2], sys.argv[3] == "true", delay)
    print("VlessServer socket integrity, actual splice transfers and orderly shutdown passed")
