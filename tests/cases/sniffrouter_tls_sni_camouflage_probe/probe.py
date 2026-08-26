#!/usr/bin/env python3

import socket
import ssl
import sys
import threading
import time
from pathlib import Path

HOST = "127.0.0.1"
LISTENER_PORT = 23770
PROTECTED_BACKEND_PORT = 23771
COVER_BACKEND_PORT = 23772

PROTECTED_SENTINEL = b"PROTECTED_APP_SENTINEL_OK\n"
FALLBACK_SENTINEL = b"FALLBACK_APP_SENTINEL_OK\n"
NGINX_400_MARKER = b"The plain HTTP request was sent to HTTPS port"

MAX_HTTP_MESSAGE_BYTES = 16 * 1024
MAX_DIAGNOSTIC_CHARS = 1024


def fail(message):
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def bounded_repr(value, max_chars=MAX_DIAGNOSTIC_CHARS):
    rendered = repr(value)
    if len(rendered) <= max_chars:
        return rendered
    return f"{rendered[:max_chars]}... <truncated; {len(rendered)} characters total>"


def recv_http_message(sock, timeout=5.0, max_bytes=MAX_HTTP_MESSAGE_BYTES):
    data = bytearray()
    deadline = time.monotonic() + timeout
    sock.settimeout(0.2)
    while time.monotonic() < deadline:
        try:
            remaining_with_overflow_byte = max_bytes - len(data) + 1
            chunk = sock.recv(min(4096, remaining_with_overflow_byte))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > max_bytes:
                raise ValueError(f"HTTP message exceeded {max_bytes} bytes")

            if b"\r\n\r\n" in data:
                header_part, body_part = bytes(data).split(b"\r\n\r\n", 1)
                content_length = None
                for line in header_part.split(b"\r\n"):
                    if line.lower().startswith(b"content-length:"):
                        try:
                            content_length = int(line.split(b":", 1)[1].strip())
                        except ValueError as exc:
                            raise ValueError("HTTP message has an invalid Content-Length") from exc
                        if content_length < 0:
                            raise ValueError("HTTP message has a negative Content-Length")
                        break

                if content_length is None or len(body_part) >= content_length:
                    return bytes(data)

                complete_length = len(header_part) + 4 + content_length
                if complete_length > max_bytes:
                    raise ValueError(
                        f"HTTP Content-Length requires {complete_length} bytes, above the {max_bytes}-byte limit"
                    )

            if len(data) == max_bytes:
                raise ValueError(f"HTTP message remained incomplete at the {max_bytes}-byte limit")
        except (socket.timeout, ssl.SSLWantReadError):
            continue
        except (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError):
            break
        except OSError:
            break
    return bytes(data)


def recv_subcase_response(sock, subcase, timeout=5.0):
    try:
        return recv_http_message(sock, timeout=timeout)
    except Exception as exc:
        fail(f"{subcase}: bounded HTTP receive failed: {exc}")


class ProtectedServer:
    def __init__(self, host, port, expected_connections):
        self.host = host
        self.port = port
        self.expected_connections = expected_connections
        self.ready_event = threading.Event()
        self.stop_event = threading.Event()
        self.connections = []
        self.conn_threads = []
        self.active_sockets = set()
        self.accepted_count = 0
        self.server_error = None
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._run, name="protected-listener", daemon=False)
        self.srv_sock = None

    def start(self):
        self.thread.start()
        if not self.ready_event.wait(timeout=5.0):
            fail("Protected backend server failed to start")
        with self.lock:
            server_error = self.server_error
        if server_error:
            fail(f"Protected backend server failed to start: {server_error}")

    def stop(self):
        self.stop_event.set()
        if self.srv_sock:
            try:
                self.srv_sock.close()
            except OSError:
                pass

        if self.thread.ident is not None:
            self.thread.join(timeout=5.0)
            if self.thread.is_alive():
                raise RuntimeError("Protected backend server thread failed to join")

        with self.lock:
            active_sockets = list(self.active_sockets)
            threads = list(self.conn_threads)

        for conn in active_sockets:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

        for t in threads:
            t.join(timeout=5.0)
            if t.is_alive():
                raise RuntimeError(f"Protected connection thread {t.name} failed to join")

        with self.lock:
            if self.active_sockets:
                raise RuntimeError("Protected backend retained active sockets after thread drain")

    def _run(self):
        try:
            self.srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.srv_sock.bind((self.host, self.port))
            self.srv_sock.listen(16)
            self.srv_sock.settimeout(0.5)
            self.ready_event.set()

            while not self.stop_event.is_set():
                try:
                    conn, _ = self.srv_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                with self.lock:
                    self.accepted_count += 1
                    connection_number = self.accepted_count
                    self.active_sockets.add(conn)

                if connection_number > self.expected_connections:
                    conn_info = {
                        "received": b"",
                        "error": (
                            f"unexpected protected connection {connection_number}; "
                            f"expected at most {self.expected_connections}"
                        ),
                    }
                    try:
                        conn.close()
                    finally:
                        with self.lock:
                            self.active_sockets.discard(conn)
                            self.connections.append(conn_info)
                    continue

                conn_thread = threading.Thread(
                    target=self._handle_conn,
                    args=(conn,),
                    name=f"protected-connection-{connection_number}",
                    daemon=False,
                )
                with self.lock:
                    self.conn_threads.append(conn_thread)
                conn_thread.start()
        except Exception as e:
            with self.lock:
                self.server_error = str(e)
            self.ready_event.set()

    def _handle_conn(self, conn):
        conn_info = {"received": b"", "error": None}
        try:
            req = recv_http_message(conn, timeout=5.0)
            conn_info["received"] = req
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: " + str(len(PROTECTED_SENTINEL)).encode("ascii") + b"\r\n"
                b"Connection: close\r\n\r\n" + PROTECTED_SENTINEL
            )
            conn.sendall(resp)
            conn.close()
        except Exception as e:
            conn_info["error"] = str(e)
            try:
                conn.close()
            except OSError:
                pass
        finally:
            with self.lock:
                self.active_sockets.discard(conn)
                self.connections.append(conn_info)


class CoverServer:
    def __init__(self, host, port, cert_file, key_file, expected_connections):
        self.host = host
        self.port = port
        self.cert_file = cert_file
        self.key_file = key_file
        self.expected_connections = expected_connections
        self.ready_event = threading.Event()
        self.stop_event = threading.Event()
        self.connections = []
        self.conn_threads = []
        self.active_sockets = set()
        self.accepted_count = 0
        self.server_error = None
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self._run, name="cover-listener", daemon=False)
        self.srv_sock = None

    def start(self):
        self.thread.start()
        if not self.ready_event.wait(timeout=5.0):
            fail("Cover server failed to start")
        with self.lock:
            server_error = self.server_error
        if server_error:
            fail(f"Cover server failed to start: {server_error}")

    def stop(self):
        self.stop_event.set()
        if self.srv_sock:
            try:
                self.srv_sock.close()
            except OSError:
                pass

        if self.thread.ident is not None:
            self.thread.join(timeout=5.0)
            if self.thread.is_alive():
                raise RuntimeError("Cover server thread failed to join")

        with self.lock:
            active_sockets = list(self.active_sockets)
            threads = list(self.conn_threads)

        for conn in active_sockets:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                conn.close()
            except OSError:
                pass

        for t in threads:
            t.join(timeout=5.0)
            if t.is_alive():
                raise RuntimeError(f"Cover connection thread {t.name} failed to join")

        with self.lock:
            if self.active_sockets:
                raise RuntimeError("Cover server retained active sockets after thread drain")

    def _run(self):
        try:
            self.srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.srv_sock.bind((self.host, self.port))
            self.srv_sock.listen(16)
            self.srv_sock.settimeout(0.5)
            self.ready_event.set()

            while not self.stop_event.is_set():
                try:
                    conn, _ = self.srv_sock.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                with self.lock:
                    self.accepted_count += 1
                    connection_number = self.accepted_count
                    self.active_sockets.add(conn)

                if connection_number > self.expected_connections:
                    conn_info = {
                        "type": None,
                        "sni": None,
                        "received": b"",
                        "error": (
                            f"unexpected cover connection {connection_number}; "
                            f"expected at most {self.expected_connections}"
                        ),
                    }
                    try:
                        conn.close()
                    finally:
                        with self.lock:
                            self.active_sockets.discard(conn)
                            self.connections.append(conn_info)
                    continue

                conn_thread = threading.Thread(
                    target=self._handle_conn,
                    args=(conn,),
                    name=f"cover-connection-{connection_number}",
                    daemon=False,
                )
                with self.lock:
                    self.conn_threads.append(conn_thread)
                conn_thread.start()
        except Exception as e:
            with self.lock:
                self.server_error = str(e)
            self.ready_event.set()

    def _handle_conn(self, conn):
        conn_info = {"type": None, "sni": None, "received": b"", "error": None}
        active_conn = conn
        try:
            conn.settimeout(5.0)
            peek_data = b""
            deadline = time.monotonic() + 5.0
            while len(peek_data) < 2 and time.monotonic() < deadline:
                try:
                    chunk = conn.recv(2, socket.MSG_PEEK)
                    if not chunk:
                        break
                    peek_data = chunk
                    if len(peek_data) < 2:
                        time.sleep(0.005)
                except socket.timeout:
                    continue

            if peek_data[:2] == b"\x16\x03":
                conn_info["type"] = "tls"
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                ctx.load_cert_chain(self.cert_file, self.key_file)

                sni_received = None

                def sni_cb(ssl_sock, servername, ssl_ctx):
                    nonlocal sni_received
                    sni_received = servername
                    return None

                ctx.set_servername_callback(sni_cb)
                with self.lock:
                    tls_sock = ctx.wrap_socket(conn, server_side=True, do_handshake_on_connect=False)
                    active_conn = tls_sock
                    self.active_sockets.discard(conn)
                    self.active_sockets.add(tls_sock)
                tls_sock.settimeout(5.0)
                tls_sock.do_handshake()
                conn_info["sni"] = sni_received

                conn_info["received"] = recv_http_message(tls_sock, timeout=5.0)

                resp = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Server: nginx\r\n"
                    b"Content-Type: text/plain\r\n"
                    b"Content-Length: " + str(len(FALLBACK_SENTINEL)).encode("ascii") + b"\r\n"
                    b"Connection: close\r\n\r\n" + FALLBACK_SENTINEL
                )
                tls_sock.sendall(resp)
                try:
                    tls_sock.unwrap()
                except OSError:
                    pass
                tls_sock.close()
            else:
                conn_info["type"] = "plain"
                conn_info["received"] = recv_http_message(conn, timeout=5.0)

                body = (
                    b"<html>\r\n"
                    b"<head><title>400 The plain HTTP request was sent to HTTPS port</title></head>\r\n"
                    b"<body>\r\n"
                    b"<center><h1>400 Bad Request</h1></center>\r\n"
                    b"<center>The plain HTTP request was sent to HTTPS port</center>\r\n"
                    b"<hr><center>nginx</center>\r\n"
                    b"</body>\r\n"
                    b"</html>\r\n"
                )
                resp = (
                    b"HTTP/1.1 400 Bad Request\r\n"
                    b"Server: nginx\r\n"
                    b"Content-Type: text/html\r\n"
                    b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                    b"Connection: close\r\n\r\n" + body
                )
                conn.sendall(resp)
                conn.close()
        except Exception as e:
            conn_info["error"] = str(e)
            try:
                active_conn.close()
            except OSError:
                pass
        finally:
            with self.lock:
                self.active_sockets.discard(conn)
                self.active_sockets.discard(active_conn)
                self.connections.append(conn_info)


def wait_for_listener(port, timeout=5.0):
    deadline = time.monotonic() + timeout
    last_err = None
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((HOST, port), timeout=0.2):
                return
        except OSError as e:
            last_err = e
            time.sleep(0.05)
    fail(f"WaterWall listener {port} did not become ready: {last_err}")


def wait_for_connections(server_obj, expected_count, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with server_obj.lock:
            if len(server_obj.connections) >= expected_count:
                return
        time.sleep(0.02)
    with server_obj.lock:
        fail(f"Timed out waiting for {server_obj.__class__.__name__} connections == {expected_count}, got {len(server_obj.connections)}")


def main():
    root = Path.cwd()
    cert_path = root / "server.crt"
    key_path = root / "server.key"
    if not cert_path.exists() or not key_path.exists():
        fail(f"Missing certificates in {root}")

    protected_srv = ProtectedServer(HOST, PROTECTED_BACKEND_PORT, expected_connections=1)
    cover_srv = CoverServer(HOST, COVER_BACKEND_PORT, str(cert_path), str(key_path), expected_connections=3)

    try:
        protected_srv.start()
        cover_srv.start()

        wait_for_listener(LISTENER_PORT, timeout=5.0)

        # 1. Expected SNI -> protected TlsServer -> protected backend
        client_ctx = ssl.create_default_context()
        client_ctx.check_hostname = False
        client_ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((HOST, LISTENER_PORT), timeout=5.0) as raw_sock:
            with client_ctx.wrap_socket(raw_sock, server_hostname="protected.integration.test") as tls_sock:
                tls_sock.sendall(b"GET /protected HTTP/1.1\r\nHost: protected.integration.test\r\n\r\n")
                resp1 = recv_subcase_response(tls_sock, "Subcase 1 (expected SNI)", timeout=5.0)

        if PROTECTED_SENTINEL not in resp1:
            fail(f"Subcase 1 (expected SNI) failed: expected protected sentinel, got {bounded_repr(resp1)}")

        wait_for_connections(protected_srv, 1, timeout=5.0)
        with cover_srv.lock:
            if cover_srv.accepted_count != 0:
                fail(f"Subcase 1 hit cover service unexpectedly: {bounded_repr(cover_srv.connections)}")
        with protected_srv.lock:
            if protected_srv.accepted_count != 1 or len(protected_srv.connections) != 1:
                fail(
                    "Subcase 1 expected one accepted and completed protected connection, "
                    f"got accepted={protected_srv.accepted_count}, completed={len(protected_srv.connections)}"
                )

        # 2. Mismatched SNI -> default route -> cover service
        with socket.create_connection((HOST, LISTENER_PORT), timeout=5.0) as raw_sock:
            with client_ctx.wrap_socket(raw_sock, server_hostname="cover.integration.test") as tls_sock:
                tls_sock.sendall(b"GET /cover HTTP/1.1\r\nHost: cover.integration.test\r\n\r\n")
                resp2 = recv_subcase_response(tls_sock, "Subcase 2 (mismatched SNI)", timeout=5.0)

        if FALLBACK_SENTINEL not in resp2:
            fail(f"Subcase 2 (mismatched SNI) failed: expected fallback sentinel, got {bounded_repr(resp2)}")

        wait_for_connections(cover_srv, 1, timeout=5.0)
        with cover_srv.lock:
            if cover_srv.accepted_count != 1 or len(cover_srv.connections) != 1:
                fail(
                    "Subcase 2 expected one accepted and completed cover connection, "
                    f"got accepted={cover_srv.accepted_count}, completed={len(cover_srv.connections)}"
                )
            conn2 = cover_srv.connections[0]
            if conn2.get("type") != "tls":
                fail(f"Subcase 2 connection type is not tls: {bounded_repr(conn2)}")
            if conn2.get("sni") != "cover.integration.test":
                fail(f"Subcase 2 recorded SNI '{conn2.get('sni')}' != 'cover.integration.test'")

        with protected_srv.lock:
            if protected_srv.accepted_count != 1 or len(protected_srv.connections) != 1:
                fail(f"Subcase 2 unexpectedly hit protected backend: {bounded_repr(protected_srv.connections)}")

        # 3. Absent SNI -> default route -> cover service
        with socket.create_connection((HOST, LISTENER_PORT), timeout=5.0) as raw_sock:
            with client_ctx.wrap_socket(raw_sock, server_hostname=None) as tls_sock:
                tls_sock.sendall(b"GET /nosni HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
                resp3 = recv_subcase_response(tls_sock, "Subcase 3 (absent SNI)", timeout=5.0)

        if FALLBACK_SENTINEL not in resp3:
            fail(f"Subcase 3 (absent SNI) failed: expected fallback sentinel, got {bounded_repr(resp3)}")

        wait_for_connections(cover_srv, 2, timeout=5.0)
        with cover_srv.lock:
            if cover_srv.accepted_count != 2 or len(cover_srv.connections) != 2:
                fail(
                    "Subcase 3 expected two accepted and completed cover connections, "
                    f"got accepted={cover_srv.accepted_count}, completed={len(cover_srv.connections)}"
                )
            conn3 = cover_srv.connections[1]
            if conn3.get("type") != "tls":
                fail(f"Subcase 3 connection type is not tls: {bounded_repr(conn3)}")
            if conn3.get("sni") is not None:
                fail(f"Subcase 3 recorded non-null SNI: {conn3.get('sni')!r}")

        with protected_srv.lock:
            if protected_srv.accepted_count != 1 or len(protected_srv.connections) != 1:
                fail(f"Subcase 3 unexpectedly hit protected backend: {bounded_repr(protected_srv.connections)}")

        # 4. Plain HTTP on public TLS port -> default route -> cover service
        plain_req = b"GET /plain HTTP/1.1\r\nHost: plain.integration.test\r\n\r\n"
        with socket.create_connection((HOST, LISTENER_PORT), timeout=5.0) as raw_sock:
            raw_sock.sendall(plain_req)
            resp4 = recv_subcase_response(raw_sock, "Subcase 4 (plain HTTP)", timeout=5.0)

        if b"400 Bad Request" not in resp4 or NGINX_400_MARKER not in resp4:
            fail(f"Subcase 4 (plain HTTP) failed: expected nginx 400 response, got {bounded_repr(resp4)}")

        wait_for_connections(cover_srv, 3, timeout=5.0)
        with cover_srv.lock:
            if cover_srv.accepted_count != 3 or len(cover_srv.connections) != 3:
                fail(
                    "Subcase 4 expected three accepted and completed cover connections, "
                    f"got accepted={cover_srv.accepted_count}, completed={len(cover_srv.connections)}"
                )
            conn4 = cover_srv.connections[2]
            if conn4.get("type") != "plain":
                fail(f"Subcase 4 connection type is not plain: {bounded_repr(conn4)}")
            received_plain = conn4.get("received", b"")
            if received_plain != plain_req:
                fail(
                    "Subcase 4 plaintext replay mismatch: "
                    f"received={bounded_repr(received_plain)}, sent={bounded_repr(plain_req)}"
                )

    finally:
        cleanup_errors = []
        for server in (protected_srv, cover_srv):
            try:
                server.stop()
            except Exception as exc:
                cleanup_errors.append(f"{server.__class__.__name__}: {exc}")
        if cleanup_errors:
            fail(f"Fixture cleanup failed: {'; '.join(cleanup_errors)}")

    # 5. Final accounting runs only after every fixture connection thread has drained.
    with protected_srv.lock:
        if protected_srv.server_error:
            fail(f"Protected listener error: {protected_srv.server_error}")
        if protected_srv.accepted_count != 1 or len(protected_srv.connections) != 1:
            fail(
                "Final accounting: expected one accepted and completed protected connection, "
                f"got accepted={protected_srv.accepted_count}, completed={len(protected_srv.connections)}"
            )
        for connection in protected_srv.connections:
            if connection.get("error"):
                fail(f"Protected connection error: {connection['error']}")

    with cover_srv.lock:
        if cover_srv.server_error:
            fail(f"Cover listener error: {cover_srv.server_error}")
        if cover_srv.accepted_count != 3 or len(cover_srv.connections) != 3:
            fail(
                "Final accounting: expected three accepted and completed cover connections, "
                f"got accepted={cover_srv.accepted_count}, completed={len(cover_srv.connections)}"
            )
        for connection in cover_srv.connections:
            if connection.get("error"):
                fail(f"Cover connection error: {connection['error']}")

    print("sniffrouter_tls_sni_camouflage_probe: all subcases passed successfully.")


if __name__ == "__main__":
    main()
