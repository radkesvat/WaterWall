#!/usr/bin/env python3
"""TrojanClient against a socket peer, with real TCP/UDP ingress in a private namespace."""
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


def exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise AssertionError(f"EOF after {len(result)} of {size} bytes")
        result.extend(chunk)
    return bytes(result)


def udp_frame(payload):
    return b"\x01\x7f\x00\x00\x01\x01\xbb" + len(payload).to_bytes(2, "big") + b"\r\n" + payload


def run(binary, udp, enabled, timeout=None, nested=False, waiting=False):
    # strace observes successful runtime transfers without adding product hooks.
    tracer = shutil.which("strace")
    if tracer is None:
        raise RuntimeError("strace is required to verify actual splice I/O")
    payloads = [b"", b"a", bytes(range(256)) * 32, b"end", b""]
    with tempfile.TemporaryDirectory(prefix="waterwall-trojan-splice-") as directory:
        root = Path(directory)
        nodes = [
            {"name": "listen", "type": "UdpListener" if udp else "TcpListener", "next": "trojan",
             "settings": {"address": "127.0.0.1", "port": 27951}},
            {"name": "trojan", "type": "TrojanClient", "next": "connect",
             "settings": {"password": "test", "address": "127.0.0.1", "port": 443,
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
        (root / "config.json").write_text(json.dumps({"name": "trojan-splice", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "log": {"path": "log/", **{name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                                      for name in ("internal", "core", "network", "dns")}},
            "configs": ["config.json"],
            "misc": {"workers": 1, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False},
        }))
        with socket.socket() as listener, (root / "stdout.log").open("w+") as log:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", 27952))
            listener.listen()
            listener.settimeout(15)
            # -D leaves the tracee as our direct child, so orderly SIGTERM and
            # wait observe WaterWall's status rather than the tracer's status.
            process = subprocess.Popen([tracer, "-D", "-f", "-e", "trace=splice", "-o", str(root / "splice.log"), binary],
                                       cwd=root, stdout=log, stderr=subprocess.STDOUT)
            try:
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
                    while True:
                        if process.poll() is not None:
                            raise AssertionError(f"startup exited {process.returncode}")
                        try:
                            client = socket.create_connection(("127.0.0.1", 27951), timeout=1)
                            break
                        except ConnectionRefusedError:
                            if time.monotonic() >= deadline:
                                raise
                            time.sleep(0.02)
                with client:
                    client.settimeout(15)
                    request = hashlib.sha224(b"test").hexdigest().encode() + b"\r\n" + (b"\x03" if udp else b"\x01")
                    request += b"\x01" + (b"\x00" * 6 if udp else b"\x7f\x00\x00\x01\x01\xbb") + b"\r\n"
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
                                    conn.sendall(wire[:1])
                                    conn.sendall(wire[1:])
                                # Send coalesced frames, including an empty one.
                                conn.sendall(udp_frame(b"one") + udp_frame(b"") + udp_frame(b"three"))
                                assert conn.recv(1) == b"", "unexpected carrier bytes during shutdown"
                            else:
                                assert exact(conn, len(early)) == early, "first TCP payload changed"
                                conn.sendall(b"server-first")
                                assert exact(conn, len(data)) == data, "upstream TCP bytes changed"
                                conn.sendall(data[::-1])
                                assert conn.recv(1) == b"", "unexpected trailing TCP bytes"

                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                        result = executor.submit(peer)
                        if udp:
                            for index, payload in enumerate(payloads):
                                assert client.send(payload) == len(payload)
                                assert client.recv(9000) == payload, "UDP payload/empty datagram changed"
                                if index == 0:
                                    trace_boundary = len((root / "splice.log").read_text())
                            assert [client.recv(9000) for _ in range(3)] == [b"one", b"", b"three"]
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
                    # No application input: the configured idle deadline must
                    # eventually emit the request and let a server-first peer reply.
                    with socket.create_connection(("127.0.0.1", 27951), timeout=15) as first_client:
                        with listener.accept()[0] as first_peer:
                            first_peer.settimeout(15)
                            assert exact(first_peer, len(request)) == request
                            first_peer.sendall(b"server-first")
                            assert exact(first_client, 12) == b"server-first"
                            first_client.shutdown(socket.SHUT_RDWR)
                            assert first_peer.recv(1) == b""
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=10) == 128 + signal.SIGTERM, "unclean shutdown"
                trace = (root / "splice.log").read_text()[trace_boundary:]
                successful = re.findall(r"(?:splice\(.*|<\.\.\. splice resumed>.*)\s= ([1-9][0-9]*)", trace)
                assert bool(successful) == enabled, f"later traffic splice evidence disagrees with enabled={enabled}"
            except BaseException:
                log.flush()
                print((root / "stdout.log").read_text(), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    binary = str(Path(sys.argv[1]).resolve())
    udp, enabled = sys.argv[2] == "udp", sys.argv[3] == "true"
    run(binary, udp, enabled)
    if not udp:
        for timeout in (23, 0):
            run(binary, False, enabled, timeout=timeout)
        run(binary, False, enabled, nested=True)
        run(binary, False, enabled, timeout=4294967295, waiting=True)
    print("TrojanClient combined bytes, idle deadlines, nested traffic, splice and shutdown passed")
