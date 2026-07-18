#!/usr/bin/env python3

import select
import socket
import ssl
import sys
import threading
import time
from pathlib import Path


HOST = "127.0.0.1"
APP_PORT = 25400
RELAY_PORT = 25401
VERIFY_APP_PORT = 25410
VERIFY_RELAY_PORT = 25411
SERVER_PORT_BASE = 25420


def fail(message):
    print(message, file=sys.stderr)
    raise SystemExit(1)


def tls12_context():
    root = Path(__file__).resolve().parent
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(root / "server.crt", root / "server.key")
    return ctx


def connect_with_retry(port, timeout=4.0):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            return socket.create_connection((HOST, port), timeout=0.5)
        except OSError as exc:
            last_error = exc
            time.sleep(0.05)
    fail(f"Waterwall listener {port} did not accept connections: {last_error}")


def recv_until_closed(sock, timeout=2.0):
    sock.settimeout(0.1)
    data = bytearray()
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            chunk = sock.recv(4096)
            if chunk == b"":
                return bytes(data), True
            data.extend(chunk)
        except (ConnectionResetError, BrokenPipeError):
            return bytes(data), True
        except socket.timeout:
            pass
    return bytes(data), False


def contains_tls_alert(records):
    pos = 0
    while pos + 5 <= len(records):
        body_len = (records[pos + 3] << 8) | records[pos + 4]
        end = pos + 5 + body_len
        if end > len(records):
            break
        if records[pos] == 0x15:
            return True
        pos = end
    return False


class TlsPeer(threading.Thread):
    def __init__(self, port, mode):
        super().__init__(daemon=True)
        self.port = port
        self.mode = mode
        self.ready = threading.Event()
        self.done = threading.Event()
        self.error = None

    def run(self):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((HOST, self.port))
                srv.listen(1)
                self.ready.set()
                raw, _ = srv.accept()
                with raw:
                    raw.settimeout(3.0)
                    with tls12_context().wrap_socket(raw, server_side=True) as tls:
                        tls.settimeout(1.0)
                        if self.mode == "verify":
                            try:
                                tls.recv(1)
                            except (OSError, ssl.SSLError):
                                pass
                            return

                        data = tls.recv(4096)
                        if self.mode == "normal":
                            if data != b"normal":
                                raise RuntimeError(f"unexpected normal payload: {data!r}")
                            tls.sendall(b"ok")
                            try:
                                tls.recv(1)
                            except (OSError, ssl.SSLError):
                                pass
                            return

                        if self.mode == "peer_close":
                            if data != b"peer-close":
                                raise RuntimeError(f"unexpected peer-close payload: {data!r}")
                            tls.settimeout(0.2)
                            try:
                                tls.unwrap()
                            except (OSError, ssl.SSLError, socket.timeout):
                                pass
                            return

                        if self.mode == "corrupt":
                            if data != b"corrupt":
                                raise RuntimeError(f"unexpected corrupt payload: {data!r}")
                            tls.sendall(b"will-be-corrupted")
                            try:
                                tls.recv(1)
                            except (OSError, ssl.SSLError):
                                pass
                            return

                        raise RuntimeError(f"unknown peer mode {self.mode}")
        except ssl.SSLError as exc:
            if self.mode != "verify":
                self.error = exc
        except BaseException as exc:
            self.error = exc
        finally:
            self.done.set()


class RecordingRelay(threading.Thread):
    def __init__(self, listen_port, target_port, corrupt_first_server_app=False, withhold_server_fin=False):
        super().__init__(daemon=True)
        self.listen_port = listen_port
        self.target_port = target_port
        self.corrupt_first_server_app = corrupt_first_server_app
        self.withhold_server_fin = withhold_server_fin
        self.ready = threading.Event()
        self.done = threading.Event()
        self.error = None
        self.c2s = bytearray()
        self.s2c = bytearray()
        self.client_eof = False

    def run(self):
        client = None
        server = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((HOST, self.listen_port))
                listener.listen(1)
                self.ready.set()
                client, _ = listener.accept()
                server = socket.create_connection((HOST, self.target_port), timeout=2.0)
                client.setblocking(False)
                server.setblocking(False)
                self._pump(client, server)
        except BaseException as exc:
            self.error = exc
        finally:
            for sock in (client, server):
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
            self.done.set()

    def _pump(self, client, server):
        sockets = [client, server]
        server_pending = bytearray()
        corrupted = False
        deadline = time.monotonic() + 4.0

        while sockets and time.monotonic() < deadline:
            readable, _, _ = select.select(sockets, [], [], 0.1)
            for sock in readable:
                try:
                    chunk = sock.recv(4096)
                except BlockingIOError:
                    continue

                if chunk == b"":
                    if sock is client:
                        self.client_eof = True
                        sockets.remove(client)
                        try:
                            server.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass
                    else:
                        sockets.remove(server)
                        if not self.withhold_server_fin:
                            try:
                                client.shutdown(socket.SHUT_WR)
                            except OSError:
                                pass
                    continue

                if sock is client:
                    self.c2s.extend(chunk)
                    server.sendall(chunk)
                else:
                    self.s2c.extend(chunk)
                    if self.corrupt_first_server_app and not corrupted:
                        server_pending.extend(chunk)
                        out, corrupted = self._drain_server_records(server_pending)
                        if out:
                            client.sendall(out)
                    else:
                        client.sendall(chunk)

            if self.client_eof:
                return

        if not self.client_eof:
            raise RuntimeError("relay did not observe client-side EOF promptly")

    @staticmethod
    def _drain_server_records(pending):
        out = bytearray()
        corrupted = False
        while len(pending) >= 5:
            body_len = (pending[3] << 8) | pending[4]
            record_len = 5 + body_len
            if len(pending) < record_len:
                break
            record = bytearray(pending[:record_len])
            del pending[:record_len]
            if not corrupted and record[0] == 0x17 and body_len > 0:
                record[-1] ^= 0x01
                corrupted = True
            out.extend(record)
        return bytes(out), corrupted


def run_relayed_scenario(name, app_port, relay_port, mode, app_payload, expect_response=None,
                         expect_app_close=False, corrupt_server_app=False, withhold_server_fin=False):
    server_port = SERVER_PORT_BASE + run_relayed_scenario.counter
    run_relayed_scenario.counter += 1

    peer = TlsPeer(server_port, mode)
    relay = RecordingRelay(relay_port, server_port, corrupt_server_app, withhold_server_fin)
    peer.start()
    relay.start()
    if not peer.ready.wait(2.0) or not relay.ready.wait(2.0):
        fail(f"{name}: peer or relay did not start")

    with connect_with_retry(app_port) as app:
        app.settimeout(1.0)
        app.sendall(app_payload)
        if expect_response is not None:
            response = app.recv(len(expect_response))
            if response != expect_response:
                fail(f"{name}: unexpected protected response {response!r}")
            app.close()
        elif expect_app_close:
            _, closed = recv_until_closed(app)
            if not closed:
                fail(f"{name}: protected side did not close promptly")

    if not relay.done.wait(3.0):
        fail(f"{name}: relay did not finish")
    if not peer.done.wait(3.0):
        fail(f"{name}: TLS peer did not finish")
    if relay.error is not None:
        fail(f"{name}: relay failed: {relay.error}")
    if peer.error is not None:
        fail(f"{name}: TLS peer failed: {peer.error}")
    if contains_tls_alert(relay.c2s):
        fail(f"{name}: TlsClient emitted a TLS alert record")
    if withhold_server_fin and not relay.client_eof:
        fail(f"{name}: TlsClient waited for server FIN")


run_relayed_scenario.counter = 0


def main():
    run_relayed_scenario("normal-close", APP_PORT, RELAY_PORT, "normal", b"normal", expect_response=b"ok")
    run_relayed_scenario("peer-close-notify", APP_PORT, RELAY_PORT, "peer_close", b"peer-close",
                         expect_app_close=True, withhold_server_fin=True)
    run_relayed_scenario("corrupt-record", APP_PORT, RELAY_PORT, "corrupt", b"corrupt",
                         expect_app_close=True, corrupt_server_app=True)
    run_relayed_scenario("verify-failure", VERIFY_APP_PORT, VERIFY_RELAY_PORT, "verify", b"verify",
                         expect_app_close=True)


if __name__ == "__main__":
    main()
