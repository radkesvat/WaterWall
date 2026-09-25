#!/usr/bin/env python3
"""HTTP proxy socket peers and endpoint-specific splice evidence; namespace only."""
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


def header(sock):
    result = bytearray()
    while not result.endswith(b"\r\n\r\n"):
        result += exact(sock, 1)
        assert len(result) <= 65536, "oversized HTTP header"
    return bytes(result)


def successful_calls(trace):
    """Join strace's per-thread resumed calls before checking socket endpoints."""
    pending = {}
    for line in trace.splitlines():
        match = re.match(r"\s*(\d+)\s+(.*)", line)
        if not match:
            continue
        tid, call = match.groups()
        if call.endswith("<unfinished ...>"):
            pending[tid] = call.removesuffix("<unfinished ...>")
            continue
        resumed = re.match(r"<\.\.\. \w+ resumed>(.*)", call)
        if resumed:
            call = pending.pop(tid, "") + resumed.group(1)
        if re.search(r"\)\s+= [1-9]\d*", call):
            yield call


def splice_outputs(trace):
    outputs = set()
    positive = False
    for call in successful_calls(trace):
        if not call.startswith("splice("):
            continue
        positive = True
        match = re.match(r"splice\(\d+<pipe:\[\d+\]>, NULL, \d+<TCP:\[([^]]+)\]>, NULL,", call)
        if match:
            endpoints = match.group(1)
            if endpoints.endswith("->127.0.0.1:27972"):
                outputs.add("up")
            if endpoints.startswith("127.0.0.1:27971->"):
                outputs.add("down")
    return positive, outputs


def check_http_reads(trace, client_port, origin_port):
    endpoints = {f"127.0.0.1:27971->127.0.0.1:{client_port}": "up",
                 f"127.0.0.1:{origin_port}->127.0.0.1:27972": "down"}
    ordinary = set()
    for call in successful_calls(trace):
        match = re.match(r"(recvfrom|splice)\(\d+<TCP:\[([^]]+)\]>,", call)
        if not match or match.group(2) not in endpoints:
            continue
        direction = endpoints[match.group(2)]
        if match.group(1) == "recvfrom":
            ordinary.add(direction)
        else:
            assert direction != "down", "HTTP child started pipe reads before applying its preference"
    assert ordinary == {"up", "down"}, ("HTTP read preferences did not reach both sockets", ordinary)


def run(binary, mode, enabled):
    tracer = shutil.which("strace")
    if tracer is None:
        raise RuntimeError("inconclusive: strace is required for pipe-to-socket evidence")
    fallback = mode == "fallback"
    tracked = mode == "tracked"
    blocked = mode == "blocked"
    credentials = b"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n" if mode in ("local", "tracked", "blocked") else b""
    settings = {"no-auth": True}
    if tracked:
        settings = {"auth-client-node-name": "auth-client"}
    elif mode in ("local", "fallback", "blocked"):
        settings = {"users": [{"username": "user", "password": "pass"}]}
    with tempfile.TemporaryDirectory(prefix="waterwall-http-splice-") as directory:
        root = Path(directory)
        nodes = [
            {"name": "listen", "type": "TcpListener", "next": "proxy",
             "settings": {"address": "127.0.0.1", "port": 27971, "nodelay": True}},
            {"name": "proxy", "type": "HttpProxyServer", "next": "connect", "settings": settings},
            {"name": "connect", "type": "TcpConnector",
             "settings": {"address": "dest_context->address", "port": "dest_context->port", "fastopen": False}},
        ]
        if tracked:
            fixture = Path(__file__).resolve().parents[1] / "tunnels/HttpProxyServer/examples/authenticated/config.json"
            nodes = json.loads(fixture.read_text())["nodes"][:2] + nodes
            (root / "users.json").write_text(json.dumps({"users": [{"id": 1001, "password": "user:pass", "enabled": True,
                                                                   "limit": {"connections-out": 1}}]}))
        if fallback or blocked:
            settings["fallback-node-name"] = "fallback"
            if blocked:
                # An unselected, merged fallback still blocks the protected chain.
                nodes.append({"name": "fallback", "type": "ObfuscatorClient", "next": "fallback-connect",
                              "settings": {"method": "xor", "xor_key": 42, "tls_record_header": True}})
            nodes.append({"name": "fallback-connect" if blocked else "fallback", "type": "TcpConnector",
                          "settings": {"address": "127.0.0.1", "port": 27972, "fastopen": False}})
        (root / "config.json").write_text(json.dumps({"name": "http-splice", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "log": {"path": "log/", **{name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                                      for name in ("internal", "core", "network", "dns")}},
            "configs": ["config.json"],
            "misc": {"workers": 1, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False},
        }))
        with socket.socket() as backend, (root / "stdout.log").open("w+") as log:
            backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            backend.bind(("127.0.0.1", 27972))
            backend.listen()
            backend.settimeout(10)
            process = subprocess.Popen([tracer, "-D", "-f", "-yy", "-e", "trace=splice,recvfrom", "-o", str(root / "splice.log"), binary],
                                       cwd=root, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 10
                while True:
                    if process.poll() is not None:
                        raise AssertionError(f"startup exited {process.returncode}")
                    try:
                        client = socket.create_connection(("127.0.0.1", 27971), timeout=1)
                        break
                    except ConnectionRefusedError:
                        if time.monotonic() >= deadline:
                            raise
                        time.sleep(.02)
                with client:
                    client.settimeout(10)
                    if tracked:
                        while "AuthenticationClient: pulled 1 users" not in (root / "stdout.log").read_text():
                            if process.poll() is not None or time.monotonic() >= deadline:
                                raise AssertionError("authentication did not become ready")
                            time.sleep(.02)
                    request = (b"GET http://untrusted.invalid:19/a HTTP/1.1\r\nHost: unchanged\r\n"
                               b"Proxy-Authorization: Basic !!!\r\n\r\noriginal-tail") if fallback else (
                               b"CONNECT 127.0.0.1:27972 HTTP/1.1\r\nHost: ignored\r\n" + credentials + b"\r\n")
                    data = bytes(range(256)) * 1024

                    def peer():
                        with backend.accept()[0] as conn:
                            conn.settimeout(10)
                            if fallback:
                                assert exact(conn, len(request)) == request, "fallback replay changed"
                            conn.sendall(b"ready")
                            assert exact(conn, len(data)) == data, "upstream opaque bytes changed"
                            conn.sendall(data[::-1])
                            assert conn.recv(1) == b"", "extra relay bytes"

                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                        result = executor.submit(peer)
                        client.sendall(request)
                        if not fallback:
                            assert header(client) == b"HTTP/1.1 200 Connection Established\r\n\r\n"
                        assert exact(client, 5) == b"ready"
                        if tracked:
                            with socket.create_connection(("127.0.0.1", 27971), timeout=5) as rejected:
                                rejected.settimeout(5)
                                rejected.sendall(request)
                                assert b"502" in header(rejected), "tracked helper did not reject second connection"
                            assert "UserController: rejected new connection: connection limit reached" in (root / "stdout.log").read_text()
                        client.sendall(data)
                        assert exact(client, len(data)) == data[::-1], "downstream opaque bytes changed"
                        client.shutdown(socket.SHUT_RDWR)
                        result.result(timeout=15)
                # Separate body deliveries exercise the listener's next receive
                # boundary after request selection, plus the child's initial mode.
                if not fallback:
                    with socket.create_connection(("127.0.0.1", 27971), timeout=5) as http:
                        http.settimeout(10)
                        http_client_port = http.getsockname()[1]
                        upload = b"body" * 16384
                        http.sendall(b"POST http://127.0.0.1:27972/a HTTP/1.0\r\nHost: ignored\r\n" + credentials +
                                     f"Content-Length: {len(upload)}\r\n\r\n".encode())
                        with backend.accept()[0] as conn:
                            conn.settimeout(10)
                            http_origin_port = conn.getpeername()[1]
                            assert header(conn).startswith(b"POST /a HTTP/1.1\r\n")
                            for part in (upload[:32768], upload[32768:]):
                                http.sendall(part)
                                assert exact(conn, len(part)) == part
                            conn.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-End\r\n\r\n"
                                         b"4\r\ndone\r\n0\r\nX-End: yes\r\n\r\n")
                            response = header(http)
                            assert response.startswith(b"HTTP/1.0 200") and b"Transfer-Encoding" not in response
                            assert exact(http, 4) == b"done" and http.recv(1) == b"", "dechunked HTTP integrity/close"
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=10) == 128 + signal.SIGTERM, "unclean shutdown"
                trace = (root / "splice.log").read_text()
                if not fallback:
                    check_http_reads(trace, http_client_port, http_origin_port)
                positive, outputs = splice_outputs(trace)
                expect = enabled and not blocked
                assert positive == expect, ("unexpected chain eligibility", trace)
                assert outputs == ({"up", "down"} if expect else set()), ("missing bidirectional pipe-to-socket output", trace)
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
    print("HTTP proxy integrity, bidirectional pipe-to-socket output and orderly shutdown passed")
