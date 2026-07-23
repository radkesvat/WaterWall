#!/usr/bin/env python3

import contextlib
import socket
import sys
import threading
import time


PROBE_PAYLOAD = b"waterwall-socket-manager-probe"


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


class MarkerServers:
    def __init__(self, *servers):
        self._servers = servers

    def __enter__(self):
        for server in self._servers:
            server.start()
        for server in self._servers:
            server.wait_ready()
        return self

    def __exit__(self, exc_type, exc, tb):
        for server in self._servers:
            server.stop()
        for server in self._servers:
            server.join()
        if exc_type is None:
            for server in self._servers:
                server.assert_no_errors()
        return False


class TcpMarkerServer:
    def __init__(self, host, port, marker):
        self.host = host
        self.port = port
        self.marker = marker
        self.errors = []
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def wait_ready(self, timeout=2.0):
        if not self._ready.wait(timeout):
            fail(f"TCP marker server {self.host}:{self.port} did not start")

    def stop(self):
        self._stop.set()
        with contextlib.suppress(OSError):
            with socket.create_connection((self.host, self.port), timeout=0.1):
                pass

    def join(self):
        self._thread.join(timeout=2.0)
        if self._thread.is_alive():
            fail(f"TCP marker server {self.host}:{self.port} did not stop")

    def assert_no_errors(self):
        if self.errors:
            fail(f"TCP marker server {self.host}:{self.port} failed: {self.errors[0]}")

    def _run(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((self.host, self.port))
                srv.listen(16)
                srv.settimeout(0.1)
                self._ready.set()

                while not self._stop.is_set():
                    try:
                        conn, _ = srv.accept()
                    except socket.timeout:
                        continue

                    with conn:
                        conn.settimeout(1.0)
                        with contextlib.suppress(OSError):
                            conn.recv(4096)
                        with contextlib.suppress(OSError):
                            conn.sendall(self.marker)
        except BaseException as exc:
            self.errors.append(repr(exc))
            self._ready.set()


class UdpMarkerServer:
    def __init__(self, host, port, marker):
        self.host = host
        self.port = port
        self.marker = marker
        self.errors = []
        self._ready = threading.Event()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()

    def wait_ready(self, timeout=2.0):
        if not self._ready.wait(timeout):
            fail(f"UDP marker server {self.host}:{self.port} did not start")

    def stop(self):
        self._stop.set()
        with contextlib.suppress(OSError):
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.sendto(b"stop", (self.host, self.port))

    def join(self):
        self._thread.join(timeout=2.0)
        if self._thread.is_alive():
            fail(f"UDP marker server {self.host}:{self.port} did not stop")

    def assert_no_errors(self):
        if self.errors:
            fail(f"UDP marker server {self.host}:{self.port} failed: {self.errors[0]}")

    def _run(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((self.host, self.port))
                srv.settimeout(0.1)
                self._ready.set()

                while not self._stop.is_set():
                    try:
                        data, peer = srv.recvfrom(4096)
                    except socket.timeout:
                        continue

                    if data:
                        with contextlib.suppress(OSError):
                            srv.sendto(self.marker, peer)
        except BaseException as exc:
            self.errors.append(repr(exc))
            self._ready.set()


def expect_tcp_marker(host, port, expected_marker, timeout=6.0):
    deadline = time.monotonic() + timeout
    last_error = None

    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5) as sock:
                sock.settimeout(1.0)
                sock.sendall(PROBE_PAYLOAD)
                data = sock.recv(4096)
                if data == expected_marker:
                    return
                if data:
                    fail(f"TCP {host}:{port} returned unexpected marker: {data!r}")
                last_error = RuntimeError("connection closed without marker")
        except (OSError, RuntimeError) as exc:
            last_error = exc
            time.sleep(0.05)

    fail(f"TCP {host}:{port} did not return {expected_marker!r}: {last_error}")


def expect_udp_marker(host, port, expected_marker, timeout=6.0):
    deadline = time.monotonic() + timeout
    last_error = None

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(0.4)
        while time.monotonic() < deadline:
            try:
                sock.sendto(PROBE_PAYLOAD, (host, port))
                data, _ = sock.recvfrom(4096)
                if data == expected_marker:
                    return
                if data:
                    fail(f"UDP {host}:{port} returned unexpected marker: {data!r}")
            except OSError as exc:
                last_error = exc
                time.sleep(0.05)

    fail(f"UDP {host}:{port} did not return {expected_marker!r}: {last_error}")
