#!/usr/bin/env python3
"""Raw loopback proxy acceptance probe. The namespace harness owns the runtime."""
import base64
import concurrent.futures
import hashlib
import os
from pathlib import Path
import queue
import socket
import threading
import time


class Wire:
    def __init__(self, sock):
        self.sock = sock
        self.buf = b""
        sock.settimeout(8)

    def exact(self, count):
        while len(self.buf) < count:
            part = self.sock.recv(65536)
            if not part:
                raise EOFError("unexpected EOF")
            self.buf += part
        data, self.buf = self.buf[:count], self.buf[count:]
        return data

    def until(self, end):
        while end not in self.buf:
            part = self.sock.recv(65536)
            if not part:
                raise EOFError("EOF before delimiter")
            self.buf += part
        offset = self.buf.index(end) + len(end)
        data, self.buf = self.buf[:offset], self.buf[offset:]
        return data

    def headers(self):
        raw = self.until(b"\r\n\r\n")
        rows = raw[:-4].split(b"\r\n")
        headers = {}
        for row in rows[1:]:
            key, value = row.split(b":", 1)
            headers[key.lower()] = value.strip()
        return rows[0], headers

    def body(self, headers):
        if b"content-length" in headers:
            return self.exact(int(headers[b"content-length"]))
        if headers.get(b"transfer-encoding") == b"chunked":
            data = b""
            while True:
                count = int(self.until(b"\r\n").split(b";", 1)[0].strip(), 16)
                if not count:
                    while self.until(b"\r\n") != b"\r\n":
                        pass
                    return data
                data += self.exact(count)
                assert self.exact(2) == b"\r\n"
        data, self.buf = self.buf, b""
        while True:
            part = self.sock.recv(65536)
            if not part:
                return data
            data += part

    def response(self, head=False):
        status, headers = self.headers()
        code = int(status.split()[1])
        body = b"" if head or code < 200 or code in (204, 304) else self.body(headers)
        return code, headers, body


class Origin:
    def __init__(self, port=0, echo=False, ipv6=False):
        self.listener = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET)
        self.listener.bind(("::1" if ipv6 else "127.0.0.1", port))
        self.listener.listen(64)
        self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.echo = echo
        self.stopped = False
        self.connections = 0
        self.requests = []
        self.errors = queue.Queue()
        self.lock = threading.Lock()
        self.slow_started = threading.Event()
        self.slow_release = threading.Event()
        self.slow_sent = threading.Event()
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stopped:
            try:
                sock, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self.lock:
                self.connections += 1
                identity = self.connections
            threading.Thread(target=self.serve, args=(sock, identity), daemon=True).start()

    def serve(self, sock, identity):
        try:
            with sock:
                if self.echo:
                    sock.sendall(b"destination-first")
                    while True:
                        data = sock.recv(65536)
                        if not data:
                            return
                        sock.sendall(data)
                wire = Wire(sock)
                while True:
                    try:
                        line, headers = wire.headers()
                    except EOFError:
                        return
                    method, path, version = line.split()
                    assert version == b"HTTP/1.1"
                    assert not path.startswith(b"http://")
                    assert b"proxy-authorization" not in headers
                    assert b"x-hop" not in headers
                    assert b"via" in headers
                    with self.lock:
                        self.requests.append((identity, method, path, headers))
                    if path == b"/early":
                        sock.sendall(b"HTTP/1.1 413 Content Too Large\r\nContent-Length: 0\r\n\r\n")
                        return
                    if headers.get(b"expect") == b"100-continue":
                        sock.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
                    upload = wire.body(headers) if b"content-length" in headers or b"transfer-encoding" in headers else b""
                    if path in (b"/slow", b"/slow-large"):
                        self.slow_started.set()
                        assert self.slow_release.wait(5), "slow response release missing"
                    if path == b"/info":
                        sock.sendall(b"HTTP/1.1 103 Early Hints\r\nLink: </a>\r\n\r\n")
                    if path == b"/chunk":
                        for piece in (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", b"3;x=1\r", b"\nabc\r\n", b"2\r\nde\r\n0\r\nX-Checksum: yes\r\n\r\n"):
                            sock.sendall(piece)
                        continue
                    if path == b"/bad":
                        sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx")
                        return
                    malformed = {
                        b"/bare-cr": b"HTTP/1.1 200 OK\r\nX: valid\r\n\rIgnored: invalid\r\nContent-Length: 0\r\n\r\n",
                        b"/eof-status": b"HTTP/1.1 20",
                        b"/eof-header": b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n",
                        b"/eof-size": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\na",
                        b"/eof-delimiter": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nx\r",
                        b"/eof-trailer": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX-Trailer: partial",
                        b"/eof-fixed": b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nx",
                    }
                    if path in malformed:
                        sock.sendall(malformed[path])
                        return
                    if path == b"/expect10":
                        assert b"expect" not in headers and upload == b"abc"
                    if path == b"/trickle":
                        sock.sendall(b"HTTP/1.1 200 ")
                        for _ in range(12):
                            time.sleep(.1)
                            sock.sendall(b"a")
                        return
                    if path == b"/close":
                        sock.sendall(b"HTTP/1.1 200 OK\r\n\r\nclose-body")
                        return
                    body = hashlib.sha256(upload).hexdigest().encode() if upload else path
                    if path == b"/large":
                        body = bytes(range(256)) * 4096
                    if path == b"/slow-large":
                        body = b"r" * 100000
                    code = b"302 Found" if path == b"/redirect" else b"200 OK"
                    sock.sendall(b"HTTP/1.1 " + code + b"\r\nContent-Length: " + str(len(body)).encode() +
                                 b"\r\nX-Connection: " + str(identity).encode() +
                                 b"\r\nSet-Cookie: a=b\r\nLocation: /elsewhere\r\n\r\n" + (b"" if method == b"HEAD" else body))
                    if path in (b"/slow", b"/slow-large"):
                        self.slow_sent.set()
        except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, EOFError):
            pass
        except Exception as exc:
            self.errors.put(exc)

    def close(self):
        self.stopped = True
        self.slow_release.set()
        self.listener.close()
        self.thread.join(2)
        if not self.errors.empty():
            raise self.errors.get()


def connect(port=29080):
    deadline = time.monotonic() + 20
    while True:
        try:
            return Wire(socket.create_connection(("127.0.0.1", port), timeout=1))
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.05)


def request(origin, path=b"/a", method=b"GET", extra=b"", version=b"1.1"):
    return method + b" http://127.0.0.1:" + str(origin.port).encode() + path + b" HTTP/" + version + b"\r\nHost: conflicting.test\r\n" + extra + b"\r\n"


def once(data, port=29080, head=False):
    wire = connect(port)
    with wire.sock:
        wire.sock.sendall(data)
        return wire.response(head)


def local_auth(pair):
    return b"Proxy-Authorization: Basic " + base64.b64encode(pair) + b"\r\n"


def local_users(a, b, sentinel, echo):
    # Run before tracked-listener traffic; local access has no account-service dependency.
    for pair in (b"alice:one", b"bob:two", b"alice:other", b"carol:two", "caf\u00e9:cl\u00e9:secret".encode()):
        assert once(request(a, extra=local_auth(pair) + b"Authorization: Bearer origin\r\n"), 29085)[0] == 200
        assert a.requests[-1][3][b"authorization"] == b"Bearer origin"
    for pair in (b"alice:one", b"bob:two"):
        wire = connect(29085)
        with wire.sock:
            wire.sock.sendall((f"CONNECT 127.0.0.1:{echo.port} HTTP/1.1\r\nHost: a\r\n").encode() + local_auth(pair) + b"\r\nearly")
            assert wire.response(head=True)[0] == 200
            assert wire.exact(len(b"destination-firstearly")) == b"destination-firstearly"
    before = a.connections
    credentials = [b"", b"Proxy-Authorization: Digest a\r\n", b"Proxy-Authorization: Basic !!!\r\n"]
    credentials += [local_auth(pair) for pair in (b"Alice:one", b"alice:One", b"alice:two", b"bob:one", b"unknown:one")]
    for extra in credentials:
        code, headers, _ = once(request(a, extra=extra), 29085)
        assert code == 407 and headers[b"proxy-authenticate"] == b'Basic realm="WaterWall"'
    assert once(request(a, extra=local_auth(b"alice:one") * 2), 29085)[0] == 400
    assert a.connections == before, "L2 refused local credentials contacted origin"
    assert once(b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n", 29085)[0] == 407
    assert once(b"OPTIONS * HTTP/1.1\r\nHost: a\r\n" + local_auth(b"alice:one") + b"\r\n", 29085)[0] == 200
    wire = connect(29085)
    with wire.sock:
        identities = []
        for _ in range(8):
            wire.sock.sendall(request(a, extra=local_auth(b"alice:one")))
            code, headers, _ = wire.response()
            assert code == 200
            identities.append(headers[b"x-connection"])
        assert len(set(identities)) == 1, "L3 local stable pair failed reuse"
        wire.sock.sendall(request(a, b"/pair-switch", extra=local_auth(b"bob:two")) +
                          request(a, b"/next", extra=local_auth(b"bob:two")))
        first, second = wire.response(), wire.response()
        assert first[2] == b"/pair-switch" and second[2] == b"/next"
        assert first[1][b"x-connection"] != identities[0]
        assert first[1][b"x-connection"] == second[1][b"x-connection"]
        before_b = b.connections
        wire.sock.sendall(request(b, extra=local_auth(b"bob:two")))
        assert wire.response()[0] == 200 and b.connections == before_b + 1
        before_requests = len(b.requests)
        wire.sock.sendall(request(b, b"/ordered", extra=local_auth(b"bob:two")) + request(b))
        assert wire.response()[2] == b"/ordered" and wire.response()[0] == 407
        assert len(b.requests) == before_requests + 1, "L3 failed reauthentication forwarded a request"
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
        data = (f"GET http://127.0.0.1:{port}/local-routed HTTP/1.1\r\nHost: a\r\n").encode()
        before = sentinel.connections
        assert once(data + local_auth(b"route:route:pass") + b"\r\n", 29085)[2] == b"/local-routed"
        assert sentinel.connections == before + 1, "L4 local Router credentials did not select route"
    print("http_proxy: L2-L4 local authentication, reauthentication, pair reuse, UTF-8 and credential routing passed")


def authentication_fallback(origin, raw_service):
    for port, pair in ((29086, b"alice:one"), (29087, b"user:pass")):
        failures = [b"", b"Proxy-Authorization: Digest x\r\n", b"Proxy-Authorization: Basic !!!\r\n",
                    local_auth(b"unknown:wrong")]
        if port == 29087:
            failures.append(local_auth(b"disabled:pass"))
        before = origin.connections
        for extra in failures:
            wire = connect(port)
            with wire.sock:
                raw = request(origin, b"/raw", b"POST", extra + b"Content-Length: 3\r\n"
                              b"Expect: 100-continue\r\nConnection: X-Hop\r\nX-Hop: value\r\n") + b"abcTAIL"
                wire.sock.sendall(raw)
                assert wire.exact(len(b"destination-first")) == b"destination-first"
                assert wire.exact(len(raw)) == raw, "fallback changed failed request bytes"
                later = request(origin, extra=local_auth(pair))
                wire.sock.sendall(later)
                assert wire.exact(len(later)) == later, "fallback returned to protected parsing"
        assert origin.connections == before, "authentication fallback contacted requested origin"
        for raw in (b"CONNECT untrusted.invalid:443 HTTP/1.1\r\nHost: a\r\n\r\nTLSbytes",
                    b"OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n",
                    b"POST http://untrusted.invalid:19/a HTTP/1.1\r\nhOsT: a\r\n"
                    b"Transfer-Encoding: chunked\r\n\r\n3;x=y\r\nabc\r\n0\r\n\r\nTAIL"):
            wire = connect(port)
            with wire.sock:
                wire.sock.sendall(raw)
                assert wire.exact(len(b"destination-first")) == b"destination-first"
                assert wire.exact(len(raw)) == raw
        before_fallback = raw_service.connections
        wire = connect(port)
        with wire.sock:
            wire.sock.sendall(request(origin, extra=local_auth(pair)))
            assert wire.response()[0] == 200
            wire.sock.sendall(request(origin))
            assert wire.response()[0] == 407
        assert once(request(origin, extra=local_auth(pair) * 2), port)[0] == 400
        assert raw_service.connections == before_fallback, "committed/malformed request selected fallback"
    print("http_proxy: local/tracked fallback exact replay, fixed-domain branch, permanent handoff and commitment passed")


def run():
    origins = [Origin(), Origin(), Origin(29083), Origin(echo=True), Origin(echo=True, ipv6=True), Origin(29088, echo=True)]
    a, b, sentinel, echo, echo6, raw_service = origins
    held = []
    try:
        local_users(a, b, sentinel, echo)
        authentication_fallback(a, raw_service)
        # Baseline assertions below count only their own new origin connections.
        a_base, b_base, sentinel_base = a.connections, b.connections, sentinel.connections
        wire = connect()
        with wire.sock:
            identities = []
            for target in (a, a, b, a):
                wire.sock.sendall(request(target))
                code, headers, body = wire.response()
                assert code == 200 and body == b"/a"
                identities.append(headers[b"x-connection"])
            assert identities[0] == identities[1] and a.connections == a_base + 2 and b.connections == b_base + 1
        for method in (b"GET", b"HEAD", b"PROPFIND"):
            code, headers, body = once(request(a, method=method), head=method == b"HEAD")
            assert code == 200 and headers[b"set-cookie"] == b"a=b"
            assert body == (b"" if method == b"HEAD" else b"/a")
        assert once(request(a, b"/redirect"))[0] == 302
        assert once(request(a, b"/chunk"))[2] == b"abcde"
        assert once(request(a, b"/chunk", version=b"1.0"))[2] == b"abcde"
        assert once(request(a, b"/close"))[2] == b"close-body"
        assert once(request(a, b"/large"))[2] == bytes(range(256)) * 4096
        assert once(request(a, b"/bad"))[0] == 502
        assert once(request(a, b"/bare-cr"))[0] == 502, "R2 malformed response accepted"
        before = a.connections
        wire = connect()
        with wire.sock:
            wire.sock.sendall(request(a, extra=b"\rIgnored: invalid\r\nContent-Length: 0\r\n"))
            assert wire.response()[0] == 400, "R2 bare CR request accepted"
            assert wire.sock.recv(1) == b"", "R2 malformed request did not close"
        assert a.connections == before, "R2 malformed request contacted origin"
        # This listener has 5s header/idle deadlines; a 2s receive deadline proves EOF settlement.
        eof_auth = b"Proxy-Authorization: Basic " + base64.b64encode(b"user:pass") + b"\r\n"
        for path in (b"/eof-status", b"/eof-header", b"/eof-size", b"/eof-delimiter", b"/eof-trailer", b"/eof-fixed"):
            wire = connect(29081)
            with wire.sock:
                wire.sock.settimeout(2)
                wire.sock.sendall(request(a, path, extra=eof_auth))
                raw = b""
                while True:
                    part = wire.sock.recv(65536)
                    if not part:
                        break
                    raw += part
                if path in (b"/eof-status", b"/eof-header"):
                    assert raw.startswith(b"HTTP/1.1 502 "), (path, raw)
                else:
                    assert raw.startswith(b"HTTP/1.1 200 ") and raw.count(b"HTTP/1.1 ") == 1, (path, raw)
                    expected_tail = {b"/eof-size": b"", b"/eof-delimiter": b"1\r\nx",
                                     b"/eof-trailer": b"0\r\n", b"/eof-fixed": b"x"}[path]
                    assert raw.split(b"\r\n\r\n", 1)[1] == expected_tail, (path, raw)
        assert once(request(a, b"/trickle"))[0] == 504, "response header trickle reset deadline"
        assert once(request(a, method=b"TRACE"))[0] == 405
        assert once(request(a, extra=b"Upgrade: websocket\r\n"))[0] == 501
        assert once(b"OPTIONS * HTTP/1.1\r\nHost: proxy\r\n\r\n")[0] == 200
        assert once(request(a, method=b"OPTIONS", extra=b"Max-Forwards: 0\r\n"))[0] == 200
        code, headers, _ = once(request(a, extra=b"Connection: X-Hop\r\nX-Hop: secret\r\nProxy-Authorization: secret\r\n"))
        assert code == 200
        upload = bytes(range(256)) * 4096  # 1 MiB, sixteen times the aggregate pending limit
        wire = connect()
        with wire.sock:
            wire.sock.sendall(request(a, b"/expect10", b"POST", b"Content-Length: 3\r\nExpect: 100-continue\r\n", b"1.0") + b"abc")
            status, headers = wire.headers()
            assert status.startswith(b"HTTP/1.0 200 "), "R4 ignored expectation was rejected or generated Continue"
            assert wire.body(headers) == hashlib.sha256(b"abc").hexdigest().encode()
            assert wire.sock.recv(1) == b"", "R4 HTTP/1.0 did not close"
        for version in (b"1.0", b"1.1"):
            assert once(request(a, extra=b"Expect: unsupported\r\n", version=version))[0] == 417
        wire = connect()
        with wire.sock:
            wire.sock.sendall(request(a, b"/upload", b"POST", b"Content-Length: " + str(len(upload)).encode() + b"\r\nExpect: 100-continue\r\n"))
            assert wire.response()[0] == 100
            wire.sock.sendall(upload)
            assert wire.response()[2] == hashlib.sha256(upload).hexdigest().encode()
        wire = connect()
        with wire.sock:
            wire.sock.sendall(request(a, b"/upload", b"POST", b"Transfer-Encoding: chunked\r\n"))
            for offset in range(0, len(upload), 8192):
                data = upload[offset:offset + 8192]
                wire.sock.sendall(b"2000;x=y\r\n" + data + b"\r\n")
            wire.sock.sendall(b"0\r\nX-Checksum: yes\r\n\r\n")
            assert wire.response()[2] == hashlib.sha256(upload).hexdigest().encode()
        wire = connect()
        with wire.sock:
            wire.sock.sendall(request(a, b"/early", b"POST", b"Content-Length: 99999\r\nExpect: 100-continue\r\n"))
            assert wire.response()[0] == 413
        wire = connect()
        with wire.sock:
            wire.sock.sendall(request(a, b"/info"))
            assert wire.response()[0] == 103 and wire.response()[0] == 200
        wire = connect()
        with wire.sock:
            before = len(b.requests)
            wire.sock.sendall(request(a, b"/slow") + request(b, b"/second"))
            assert a.slow_started.wait(3)
            assert len(b.requests) == before, "second request overtook slow response"
            a.slow_release.set()
            assert wire.response()[2] == b"/slow"
            assert wire.response()[2] == b"/second"
        for size, path in ((10000, b"/slow"), (50000, b"/slow"), (50000, b"/slow-large")):
            a.slow_started.clear()
            a.slow_release.clear()
            a.slow_sent.clear()
            upload = b"p" * size
            wire = connect()
            with wire.sock:
                before = len(a.requests)
                pipeline = request(a, path) + request(a, b"/pipeline-upload", b"POST",
                                                     b"Content-Length: " + str(size).encode() + b"\r\n") + upload
                assert len(pipeline) < 65536
                wire.sock.sendall(pipeline)
                assert a.slow_started.wait(3), "R1 origin did not receive first request"
                assert len(a.requests) == before + 1, "R1 second request forwarded prematurely"
                a.slow_release.set()
                assert a.slow_sent.wait(3), "R1 origin did not send first response"
                wire.sock.settimeout(3)  # Shorter than the 5s idle deadline.
                first = wire.response()
                second = wire.response()
                assert first[0] == 200 and first[2] == (b"r" * 100000 if path == b"/slow-large" else b"/slow")
                assert second[0] == 200 and second[2] == hashlib.sha256(upload).hexdigest().encode()
                assert first[1][b"x-connection"] == second[1][b"x-connection"], "R1 replay/reconnect"
                assert len(a.requests) == before + 2, "R1 request replay"
        print("http_proxy: R1 pipeline pressure, R2 complete headers, R3 prompt EOF, R4 HTTP/1.0 Expect passed")
        for target, host in ((echo, "127.0.0.1"), (echo, "localhost"), (echo6, "[::1]")):
            wire = connect()
            with wire.sock:
                data = ("CONNECT %s:%d HTTP/1.1\r\nHost: proxy\r\n\r\n" % (host, target.port)).encode()
                wire.sock.sendall(data[:9])
                wire.sock.sendall(data[9:] + b"early")
                assert wire.response(head=True)[0] == 200
                assert wire.exact(len(b"destination-firstearly")) == b"destination-firstearly"
                binary = bytes(range(256)) * 100
                wire.sock.sendall(binary)
                assert wire.exact(len(binary)) == binary
                wire.sock.shutdown(socket.SHUT_WR)
                assert wire.sock.recv(1) == b"", "current EOF closure contract"
        before = a.connections
        for credential in (None, b"Basic !!!", b"Basic " + base64.b64encode(b"disabled:pass")):
            extra = b"" if credential is None else b"Proxy-Authorization: " + credential + b"\r\n"
            code, headers, _ = once(request(a, extra=extra), 29081)
            assert code == 407 and headers[b"proxy-authenticate"] == b'Basic realm="WaterWall"'
        assert a.connections == before, "auth refusal contacted destination"
        quota = b"Proxy-Authorization: Basic " + base64.b64encode(b"quota:pass") + b"\r\n"
        assert once(request(a, extra=quota), 29081)[0] == 502
        before = a.connections
        assert once(request(a, extra=quota), 29081)[0] == 407
        assert a.connections == before, "quota rejection reconnected to destination"
        single = b"Proxy-Authorization: Basic " + base64.b64encode(b"single:pass") + b"\r\n"
        wire = connect(29081)
        with wire.sock:
            wire.sock.sendall(request(a, extra=single))
            assert wire.response()[0] == 200
            before = a.connections
            assert once(request(a, extra=single), 29081)[0] == 502
            assert a.connections == before, "connection admission bypassed UserController"
        deadline = time.monotonic() + 3
        while True:
            result = once(request(a, extra=single), 29081)[0]
            if result == 200:
                break
            assert result == 502 and time.monotonic() < deadline, "connection accounting was not released"
            time.sleep(.02)
        wire = connect(29081)
        with wire.sock:
            identities = []
            for user in [b"user:pass"] * 6 + [b"other:pass"]:
                wire.sock.sendall(request(a, extra=b"Proxy-Authorization: Basic " + base64.b64encode(user) + b"\r\n"))
                code, headers, _ = wire.response()
                assert code == 200
                identities.append(headers[b"x-connection"])
            # The real auth service can publish a new snapshot while accounting changes;
            # a generation change correctly replaces the child even for identical credentials.
            assert any(left == right for left, right in zip(identities[:5], identities[1:6])), identities
            assert identities[6] != identities[5], identities
            wire.sock.sendall(request(a))
            assert wire.response()[0] == 407, "reuse skipped authentication"
        before = a.connections
        for extra in (b"Content-Length: 1\r\nContent-Length: 1\r\n", b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n"):
            assert once(request(a, extra=extra))[0] == 400
        assert a.connections == before
        assert once(request(a, extra=b"X-Large: " + b"a" * 32768 + b"\r\n"))[0] == 431
        wire = connect()
        with wire.sock:
            wire.sock.sendall(b"GET http://")
            assert wire.response()[0] == 408
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
            assert once((f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: a\r\n\r\n").encode())[0] in (502, 504)
            # Requested transport is unavailable: only the configured Router branch can reach the sentinel.
            data = (f"GET http://127.0.0.1:{port}/routed HTTP/1.1\r\nHost: a\r\n\r\n").encode()
            assert once(data, 29082)[2] == b"/routed"
        assert sentinel.connections == sentinel_base + 1
        wire = connect(29084)
        with wire.sock:
            wire.sock.sendall(b"\x05\x01\x00")
            assert wire.exact(2) == b"\x05\x00"
        def parallel(_):
            assert once(request(a))[2] == b"/a"
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
            list(executor.map(parallel, range(32)))
        print("http_proxy: forwarding, framing, reuse, CONNECT, auth, routing, limits, and concurrency passed")
        if os.environ.get("HTTP_PROXY_STOP_PROBE") == "1":
            incomplete = connect()
            incomplete.sock.sendall(b"GET http://")
            held.append(incomplete)
            idle = connect()
            idle.sock.sendall(request(a))
            assert idle.response()[0] == 200
            held.append(idle)
            upload_wait = connect()
            upload_wait.sock.sendall(request(a, b"/upload", b"POST", b"Content-Length: 1000000\r\n") + b"x" * 1024)
            held.append(upload_wait)
            relay = connect()
            relay.sock.sendall((f"CONNECT 127.0.0.1:{echo.port} HTTP/1.1\r\nHost: a\r\n\r\n").encode())
            assert relay.response(head=True)[0] == 200
            assert relay.exact(len(b"destination-first")) == b"destination-first"
            held.append(relay)
            local_idle = connect(29085)
            local_idle.sock.sendall(request(a, extra=local_auth(b"alice:one")))
            assert local_idle.response()[0] == 200
            held.append(local_idle)
            local_relay = connect(29085)
            local_relay.sock.sendall((f"CONNECT 127.0.0.1:{echo.port} HTTP/1.1\r\nHost: a\r\n").encode() +
                                     local_auth(b"bob:two") + b"\r\n")
            assert local_relay.response(head=True)[0] == 200
            assert local_relay.exact(len(b"destination-first")) == b"destination-first"
            held.append(local_relay)
            raw_pending = connect(29086)
            raw_pending.sock.sendall(request(a))
            assert raw_pending.exact(len(b"destination-first")) == b"destination-first"
            assert raw_pending.exact(len(request(a))) == request(a)
            held.append(raw_pending)
            Path("stop-probe-ready").touch()
            deadline = time.monotonic() + 30
            while not Path("stop-probe-complete").exists():
                assert time.monotonic() < deadline, "native stop coordinator did not complete"
                time.sleep(.02)
            for pending in held:
                try:
                    assert pending.sock.recv(1) == b"", "runtime retained a live connection after stop"
                except (ConnectionResetError, ConnectionAbortedError):
                    pass
            print("http_proxy: native stop closed incomplete headers, idle child, upload, and CONNECT")
    finally:
        for pending in held:
            pending.sock.close()
        for origin in origins:
            origin.close()


if __name__ == "__main__":
    if os.environ.get("HTTP_PROXY_LOCAL_EXAMPLE") == "1":
        origin = Origin()
        try:
            for pair in (b"alice:replace-alice-password", b"bob:replace-bob-password"):
                assert once(request(origin, extra=local_auth(pair)), 8080)[2] == b"/a"
            assert once(request(origin), 8080)[0] == 407
            print("http_proxy: L1/L6 standalone local-users example passed without account services or database")
        finally:
            origin.close()
    else:
        run()
