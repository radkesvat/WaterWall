#!/usr/bin/env python3
"""Namespace-only client wire tests, staged body ranges, and proxy interoperability."""
import concurrent.futures
import json
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time

sys.dont_write_bytecode = True
from httpproxyserver_splice_integration import exact, header, splice_outputs


def read_chunked(sock, size):
    data = bytearray()
    while len(data) < size:
        line = bytearray()
        while not line.endswith(b"\r\n"):
            line += exact(sock, 1)
            assert len(line) <= 32
        count = int(line[:-2], 16)
        assert count and count <= size - len(data), "unexpected request chunk"
        data += exact(sock, count)
        assert exact(sock, 2) == b"\r\n", "missing immediate chunk suffix"
    return bytes(data)


def run(binary, mode, enabled, auth):
    tracer = shutil.which("strace")
    if tracer is None:
        raise RuntimeError("inconclusive: strace required for pipe-to-socket evidence")
    local_dns = mode in ("resolve_fixed", "resolve_dynamic", "resolve_branch")
    dynamic_dns = mode == "resolve_dynamic"
    branch_dns = mode == "resolve_branch"
    connect = mode == "connect" or local_dns
    chunked = mode == "chunked"
    interop = auth not in ("direct", "tls")
    data = bytes(range(256)) * 1024
    origin = "127.0.0.1" if interop else "origin.example"
    settings = {"target-address": origin, "port": 27972}
    if not connect:
        settings.update({"mode": "http", "method": "POST", "path": "/upload?q=%2F",
                         "body-mode": "chunked" if chunked else "fixed",
                         "headers": {"Content-Type": "application/octet-stream"}})
        if not chunked:
            settings["content-length"] = len(data)
    if auth in ("direct", "tls", "local", "tracked"):
        settings.update({"username": "user", "password": "pass"})
    if local_dns:
        settings["domain-strategy"] = "resolve-domains-and-use-only-ipv4"
        if dynamic_dns:
            settings.update({"target-address": "dest_context->address", "port": "dest_context->port"})
    with tempfile.TemporaryDirectory(prefix="waterwall-http-client-") as directory:
        root = Path(directory)
        nodes = [
            {"name": "listen", "type": "TcpListener", "next": "client",
             "settings": {"address": "127.0.0.1", "port": 27971, "nodelay": True}},
            {"name": "client", "type": "HttpProxyClient", "next": "transport", "settings": settings},
            {"name": "transport", "type": "TcpConnector",
             "settings": {"address": "127.0.0.1", "port": 27973 if interop else 27972, "fastopen": False}},
        ]
        if local_dns:
            (root / "hosts").write_text("127.0.0.20 origin.example\n::1 proxy.example\n")
            nodes[0]["next"] = "origin-input" if dynamic_dns else "router" if branch_dns else "client"
            nodes[2]["settings"].update({"address": "proxy.example", "domain-strategy": "only-ipv6"})
            if branch_dns:
                nodes.extend([
                    {"name": "router", "type": "Router", "next": "unused",
                     "settings": {"rules": [{"source-port": 27971, "target": "client"}]}},
                    {"name": "unused", "type": "TcpConnector",
                     "settings": {"address": "127.0.0.1", "port": 9}},
                ])
            if dynamic_dns:
                nodes.append({"name": "origin-input", "type": "HttpProxyServer", "next": "client",
                              "settings": {"no-auth": True}})
        if auth == "tls":
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=proxy.test", "-keyout", str(root / "server.key"),
                            "-out", str(root / "server.crt")], check=True, capture_output=True)
            nodes[1]["next"] = "tls-client"
            nodes.extend([
                {"name": "tls-client", "type": "TlsClient", "next": "tls-server",
                 "settings": {"sni": "proxy.test", "verify": False, "alpns": ["http/1.1"]}},
                {"name": "tls-server", "type": "TlsServer", "next": "transport",
                 "settings": {"sni": "proxy.test", "cert-file": "server.crt", "key-file": "server.key"}},
            ])
        if interop:
            proxy_settings = {"no-auth": True}
            if auth == "local":
                proxy_settings = {"users": [{"username": "user", "password": "pass"}]}
            if auth == "tracked":
                fixture = Path(__file__).resolve().parents[1] / "tunnels/HttpProxyServer/examples/authenticated/config.json"
                nodes = json.loads(fixture.read_text())["nodes"][:2] + nodes
                proxy_settings = {"auth-client-node-name": "auth-client"}
                (root / "users.json").write_text(json.dumps({"users": [{"id": 1001, "password": "user:pass", "enabled": True}]}))
            nodes.extend([
                {"name": "proxy-listen", "type": "TcpListener", "next": "proxy-server",
                 "settings": {"address": "127.0.0.1", "port": 27973}},
                {"name": "proxy-server", "type": "HttpProxyServer", "next": "origin", "settings": proxy_settings},
                {"name": "origin", "type": "TcpConnector",
                 "settings": {"address": "dest_context->address", "port": "dest_context->port", "fastopen": False}},
            ])
        (root / "config.json").write_text(json.dumps({"name": "http-client", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "log": {"path": "log/", **{name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                                      for name in ("internal", "core", "network", "dns")}},
            "configs": ["config.json"],
            **({"dns": {"lookups": "f", "hosts-path": str(root / "hosts")}} if local_dns else {}),
            "misc": {"workers": 1, "splice": enabled, "ram-profile": "minimal", "mtu": 1500,
                     "try-enabling-bbr": False},
        }))
        staged = threading.Event()
        with socket.socket(socket.AF_INET6 if local_dns else socket.AF_INET) as backend, (root / "stdout.log").open("w+") as log:
            backend.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            backend.bind(("::1" if local_dns else "127.0.0.1", 27972))
            backend.listen()
            backend.settimeout(15)
            process = subprocess.Popen([tracer, "-D", "-f", "-yy", "-e", "trace=splice", "-o", str(root / "splice.log"), binary],
                                       cwd=root, stdout=log, stderr=subprocess.STDOUT)
            try:
                deadline = time.monotonic() + 15
                if auth == "tracked":
                    while "AuthenticationClient: pulled 1 users" not in (root / "stdout.log").read_text():
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise AssertionError("authentication did not become ready")
                        time.sleep(.02)
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

                if dynamic_dns:
                    client.sendall(b"CONNECT origin.example:27972 HTTP/1.1\r\nHost: origin.example:27972\r\n\r\n")
                    assert header(client).startswith(b"HTTP/1.1 200 ")

                def peer():
                    with backend.accept()[0] as conn:
                        conn.settimeout(15)
                        if not (connect and interop):
                            request = header(conn)
                            wire_origin = "127.0.0.20" if local_dns else origin
                            target = f"{wire_origin}:27972" if connect else (
                                "/upload?q=%2F" if interop else f"http://{origin}:27972/upload?q=%2F")
                            method = "CONNECT" if connect else "POST"
                            assert request.startswith(f"{method} {target} HTTP/1.1\r\n".encode()), request
                            assert f"Host: {wire_origin}:27972\r\n".encode() in request, request
                            assert (b"Proxy-Authorization: Basic dXNlcjpwYXNz\r\n" in request) == (auth in ("direct", "tls")), request
                            if not connect:
                                if not interop:
                                    assert b"Connection: close\r\n" in request, request
                                if chunked:
                                    assert b"Transfer-Encoding: chunked\r\n" in request, request
                                else:
                                    assert f"Content-Length: {len(data)}\r\n".encode() in request, request
                        if interop and not connect:
                            uploaded = read_chunked(conn, len(data)) if chunked else exact(conn, len(data))
                            assert uploaded == data, "interoperable upload changed"
                        if connect:
                            if not interop:
                                conn.sendall(b"HTTP/1.1 200 Established\r\nContent-Length: 0\r\n\r\n")
                            conn.sendall(b"ready")
                        else:
                            framing = (b"Transfer-Encoding: chunked\r\n" if mode == "response_chunked" else
                                       b"" if mode == "response_eof" else f"Content-Length: {5 + len(data)}\r\n".encode())
                            conn.sendall(b"HTTP/1.1 200 OK\r\n" + framing + b"\r\n" +
                                         (f"{5 + len(data):x}\r\n".encode() if mode == "response_chunked" else b"") + b"ready")
                        # The application's receipt of the marker proves that the
                        # response header/chunk size has left the client's parser.
                        assert staged.wait(10), "response header did not progress"
                        if not interop or connect:
                            uploaded = read_chunked(conn, len(data)) if chunked else exact(conn, len(data))
                            assert uploaded == data, "upload framing/content changed"
                        conn.sendall(data[::-1])
                        if mode == "response_chunked":
                            conn.sendall(b"\r\n0\r\nX-Check: yes\r\n\r\n")
                        if mode == "response_eof":
                            conn.shutdown(socket.SHUT_WR)
                        if connect:
                            assert conn.recv(1) == b"", "extra CONNECT bytes"
                        else:
                            # The finite response closes the exchange even though
                            # this peer otherwise keeps its write direction open.
                            assert conn.recv(1) == b"", "extra request after response completion"

                with client, concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    client.settimeout(15)
                    future = executor.submit(peer)
                    if interop and not connect:
                        # HttpProxyServer cancels incomplete uploads on a final
                        # response. Send the body first, but keep chunked upload
                        # open: no WaterWall half-close or terminal chunk needed.
                        client.sendall(data)
                    assert exact(client, 5) == b"ready", "immediate headers or early response stalled"
                    staged.set()
                    if not interop or connect:
                        client.sendall(data)
                    assert exact(client, len(data)) == data[::-1], "decoded response changed"
                    if connect:
                        client.shutdown(socket.SHUT_RDWR)
                    else:
                        assert client.recv(1) == b"", "finite response did not close"
                    future.result(timeout=15)
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=10) == 128 + signal.SIGTERM, "unclean shutdown"
                trace = (root / "splice.log").read_text()
                if local_dns:
                    # The shared decoder recognizes IPv4 loopback endpoints;
                    # normalize this fixture's IPv6 loopback socket annotation.
                    trace = trace.replace("TCPv6:", "TCP:").replace("[::1]", "127.0.0.1")
                positive, outputs = splice_outputs(trace)
                if not interop:
                    expected = enabled and auth != "tls" and not branch_dns
                    assert positive == expected, "splice mode/topology gate"
                    assert outputs == ({"up", "down"} if expected else set()), ("missing direct body splice", outputs)
            except BaseException:
                staged.set()
                log.flush()
                print((root / "stdout.log").read_text(), file=sys.stderr)
                raise
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


def pending_shutdown(binary):
    """A real outstanding async DNS request must settle during process shutdown."""
    with tempfile.TemporaryDirectory(prefix="waterwall-http-client-pending-") as directory:
        root = Path(directory)
        nodes = [
            {"name": "listen", "type": "TcpListener", "next": "client",
             "settings": {"address": "127.0.0.1", "port": 27971}},
            {"name": "client", "type": "HttpProxyClient", "next": "transport",
             "settings": {"target-address": "pending.test", "port": 443,
                          "domain-strategy": "resolve-domains-and-prefer-ipv4"}},
            {"name": "transport", "type": "TcpConnector",
             "settings": {"address": "127.0.0.1", "port": 27972}},
        ]
        (root / "config.json").write_text(json.dumps({"name": "pending", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({
            "configs": ["config.json"],
            "dns": {"lookups": "b", "servers": ["127.0.0.1:27974"]},
            "misc": {"workers": 1, "ram-profile": "minimal", "try-enabling-bbr": False},
        }))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as dns, socket.socket() as backend:
            dns.bind(("127.0.0.1", 27974))
            dns.settimeout(10)
            backend.bind(("127.0.0.1", 27972))
            backend.listen()
            backend.settimeout(.1)
            with (root / "stdout.log").open("w+") as log:
                process = subprocess.Popen([binary], cwd=root, stdout=log, stderr=subprocess.STDOUT)
                try:
                    deadline = time.monotonic() + 10
                    while True:
                        try:
                            client = socket.create_connection(("127.0.0.1", 27971), timeout=1)
                            break
                        except ConnectionRefusedError:
                            if process.poll() is not None or time.monotonic() >= deadline:
                                raise
                            time.sleep(.02)
                    with client:
                        client.sendall(b"retained during DNS")
                        query, _ = dns.recvfrom(4096)
                        assert b"pending" in query, "unexpected DNS request"
                        process.send_signal(signal.SIGTERM)
                        assert process.wait(timeout=10) == 128 + signal.SIGTERM, "pending DNS shutdown failed"
                        try:
                            conn, _ = backend.accept()
                        except socket.timeout:
                            pass
                        else:
                            conn.close()
                            raise AssertionError("transport started before origin DNS")
                except BaseException:
                    log.flush()
                    print((root / "stdout.log").read_text(), file=sys.stderr)
                    raise
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait()


if __name__ == "__main__":
    if sys.argv[2] == "pending_shutdown":
        pending_shutdown(str(Path(sys.argv[1]).resolve()))
    else:
        run(str(Path(sys.argv[1]).resolve()), sys.argv[2], sys.argv[3] == "true", sys.argv[4])
    print("HttpProxyClient wire, body integrity, splice and shutdown passed")
