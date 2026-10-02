#!/usr/bin/env python3
"""UUID request/response and addon framing; TCP early, nested, server-first and cancellable idle waits;
UDP distinct frames. One worker/loopback peer, positive bulk splice and shutdown143. Requires strace
and namespace isolation; raw socket timeout behavior is retained. CTest:
waterwall.vlessclient_tcp_splice_false, waterwall.vlessclient_tcp_splice_true,
waterwall.vlessclient_udp_splice_false, waterwall.vlessclient_udp_splice_true."""
import concurrent.futures
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
from wwtest.sockets import configure_listener, connect_when_ready
from wwtest.config import core_config
from wwtest.trace import positive_splice_counts
from wwtest.sockets import exact as read_exact
from wwtest.run_directory import RunDirectory
from wwtest.process import Process, close_on_error, install_termination_handler




def exact(sock, size):
    return read_exact(sock, size, timeout_context=False)


def udp_frame(payload):
    return len(payload).to_bytes(2, "big") + payload


def run(binary, udp, enabled, timeout=None, nested=False, waiting=False):
    # strace observes successful runtime transfers without adding product hooks.
    tracer = shutil.which("strace")
    if tracer is None:
        raise RuntimeError("strace is required to verify actual splice I/O")
    payloads = [b"a", bytes(range(256)) * 128, b"end"]
    with RunDirectory("waterwall-vless-splice-") as directory:
        root = Path(directory)
        nodes = [
            {"name": "listen", "type": "UdpListener" if udp else "TcpListener", "next": "vless",
             "settings": {"address": "127.0.0.1", "port": 27951}},
            {"name": "vless", "type": "VlessClient", "next": "connect",
             "settings": {"uuid": "5783a3e7-e373-51cd-8642-c83782b807c5", "address": "127.0.0.1", "port": 443,
                          "protocol": "dest_context->protocol",
                          "domain-strategy": "resolve-domains-and-prefer-ipv4"}},
            {"name": "connect", "type": "TcpConnector",
             "settings": {"address": "127.0.0.1", "port": 27952, "nodelay": True, "fastopen": False}},
        ]
        if timeout is not None:
            nodes[1]["settings"]["first-payload-timeout-ms"] = timeout
        if nested:
            # Both transforms must materialize their own first header/body and
            # preserve later opaque traffic. Native tests assert one callback.
            nodes[1]["next"] = "nested"
            inner = json.loads(json.dumps(nodes[1]))
            inner.update(name="nested", next="connect")
            inner["settings"]["protocol"] = "tcp"
            nodes.insert(2, inner)
        (root / "config.json").write_text(json.dumps({"name": "vless-splice", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "log": core_config()["log"],
            "configs": ["config.json"],
            "misc": {"workers": 1, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False},
        }))
        with socket.socket() as listener, (root / "stdout.log").open("w+") as log:
            configure_listener(listener, ('127.0.0.1', 27952), timeout=15)
            # -D leaves the tracee as our direct child, so orderly SIGTERM and
            # wait observe WaterWall's status rather than the tracer's status.
            with Process([tracer, '-D', '-f', '-e', 'trace=splice', '-o', str(root / 'splice.log'), binary], cwd=root, log=log) as process:
                deadline = time.monotonic() + 10
                if udp:
                    # Wait for the actual listener publication, without probing
                    # a UDP peer into a second association.
                    while "listening" not in (root / "stdout.log").read_text().lower():
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise AssertionError("UDP listener did not start")
                        time.sleep(0.02)
                    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    client.connect(("127.0.0.1", 27951))
                else:
                    client = connect_when_ready(process, ('127.0.0.1', 27951), deadline=deadline,
                        failure=lambda: AssertionError(f'startup exited {process.returncode}'), timeout=1, pause=0.02)
                with client:
                    client.settimeout(15)
                    request = b"\0" + uuid.UUID("5783a3e7-e373-51cd-8642-c83782b807c5").bytes
                    request += b"\0" + (b"\2" if udp else b"\1") + b"\1\xbb\1\x7f\0\0\1"
                    data = bytes(range(256)) * 4096
                    if nested:
                        request = request + request
                    early = data if nested else b"early"
                    trace_boundary = 0
                    if waiting:
                        with listener.accept()[0] as waiting_peer:
                            waiting_peer.settimeout(0.1)
                            try:
                                unexpected = waiting_peer.recv(1)
                            except socket.timeout:
                                pass
                            else:
                                raise AssertionError(f"waiting carrier unexpectedly produced {unexpected!r}")
                            waiting_peer.settimeout(10)
                            # A maximum deadline must remain cancellable, without
                            # holding a dead connection until that deadline.
                            process.send_signal(signal.SIGTERM)
                            assert process.wait(timeout=10) == 128 + signal.SIGTERM
                            assert waiting_peer.recv(1) == b"", "shutdown emitted an idle header"
                        return

                    def peer():
                        with listener.accept()[0] as conn:
                            conn.settimeout(15)
                            assert exact(conn, len(request)) == request, "request encoding/command changed"
                            if udp:
                                for index, payload in enumerate(payloads):
                                    wire = udp_frame(payload)
                                    assert exact(conn, len(wire)) == wire, "UDP framing or boundary changed"
                                    if index == 0:
                                        # Withhold response until first application datagram arrives.
                                        conn.sendall(b"\0\3add")
                                    conn.sendall(wire[:1])
                                    conn.sendall(wire[1:])
                                # Send coalesced frames with distinct datagram boundaries.
                                conn.sendall(udp_frame(b"one") + udp_frame(b"two") + udp_frame(b"three"))
                                assert conn.recv(1) == b"", "unexpected carrier bytes during shutdown"
                            else:
                                assert exact(conn, len(early)) == early, "TCP outbound waited for response"
                                conn.sendall(b"\0\3add" * (2 if nested else 1) + b"server-first")
                                assert exact(conn, len(data)) == data, "upstream TCP bytes changed"
                                conn.sendall(data[::-1])
                                assert conn.recv(1) == b"", "unexpected trailing TCP bytes"

                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor, close_on_error(client):
                        result = executor.submit(peer)
                        if udp:
                            for index, payload in enumerate(payloads):
                                assert client.send(payload) == len(payload)
                                assert client.recv(65535) == payload, "UDP payload changed"
                                if index == 0:
                                    trace_boundary = len((root / "splice.log").read_text())
                            assert [client.recv(65535) for _ in range(3)] == [b"one", b"two", b"three"]
                            # The association is still live: shutdown must drain its owned carrier.
                            process.send_signal(signal.SIGTERM)
                            assert process.wait(timeout=10) == 128 + signal.SIGTERM, "unclean UDP shutdown"
                        else:
                            client.sendall(early)
                            assert exact(client, 12) == b"server-first", "request waited for application data"
                            trace_boundary = len((root / "splice.log").read_text())
                            client.sendall(data)
                            assert exact(client, len(data)) == data[::-1], "downstream TCP bytes changed"
                            client.shutdown(socket.SHUT_RDWR)
                        result.result(timeout=20)
                if not udp:
                    # A separate connection proves server-first operation with no
                    # application payload at all before request and response.
                    with socket.create_connection(("127.0.0.1", 27951), timeout=15) as first_client:
                        with listener.accept()[0] as first_peer:
                            first_peer.settimeout(15)
                            assert exact(first_peer, len(request)) == request
                            first_peer.sendall(b"\0\1x" * (2 if nested else 1) + b"server-first")
                            assert exact(first_client, 12) == b"server-first"
                            first_client.shutdown(socket.SHUT_RDWR)
                            assert first_peer.recv(1) == b""
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=10) == 128 + signal.SIGTERM, "unclean shutdown"
                trace = (root / "splice.log").read_text()[trace_boundary:]
                successful = positive_splice_counts(trace)
                assert bool(successful) == enabled, f"later traffic splice evidence disagrees with enabled={enabled}"


if __name__ == "__main__":
    install_termination_handler()
    binary = str(Path(sys.argv[1]).resolve())
    udp, enabled = sys.argv[2] == "udp", sys.argv[3] == "true"
    run(binary, udp, enabled)
    if not udp:
        for timeout in (23, 0):
            run(binary, False, enabled, timeout=timeout)
        run(binary, False, enabled, nested=True)
        run(binary, False, enabled, timeout=4294967295, waiting=True)
    print("VlessClient combined bytes, idle deadlines, nested traffic, splice and shutdown passed")
