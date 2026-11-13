#!/usr/bin/env python3
"""ConnectionStripe stream aggregation over real TCP, TLS/TCP and KCP/UDP.

Each application session creates eight full-duplex carriers and exactly one
backend connection. Three concurrent sessions exchange distinct 2 MiB bodies in
both directions after a server-first greeting, exercise both EOF directions, and
leave a final session alive during orderly runtime shutdown. The TCP relay counts
lane identities and verifies every carrier transports application data in both
directions. It forwards later DATA before held earlier DATA, forwards CLOSE
before held DATA in both directions, drops a carrier from another session, and
checks expiry of an incomplete introduction and an incomplete carrier group.
Four workers exercise actual worker handoff. Explicit splice on/off TCP variants
check post-setup pipe-to-socket output at all four endpoints using strace; TLS
and KCP remain splice blockers for their complete chains.
All sockets use the namespace harness's private loopback network. This verifies
correctness; it makes no assertion about throughput improvement.
CTest: waterwall.connection_stripe_{tcp,tls,kcp}.

The --mux cases use one worker and one fixed Mux parent, with eight carriers.
Three client-first application streams exchange distinct full-duplex bodies;
closing children in both directions leaves a sibling usable. A later child
reuses the same group, verified by the relay's cumulative TCP accept count
(TLS is forwarded opaquely). Each child opens its own service connection.
CTest: waterwall.connection_stripe_mux_{tcp,tls} and
waterwall.connection_stripe_{tcp,mux_tcp}_splice_false. The existing TCP cases
exercise splice enabled; the explicit false variants exercise ordinary I/O.
"""

import argparse
import concurrent.futures
import contextlib
import json
import os
import re
from pathlib import Path
import select
import shutil
import signal
import socket
import struct
import sys
import threading
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.config import core_config
from wwtest.process import Process, close_on_error, install_termination_handler
from wwtest.run_directory import RunDirectory
from wwtest.sockets import configure_listener, connect_when_ready, exact
from wwtest.trace import successful_calls


HOST = "127.0.0.1"
APP_PORT, WIRE_PORT, BACKEND_PORT, RELAY_PORT = 29931, 29932, 29933, 29934
CERTIFICATES = Path(__file__).resolve().parent / "speedtests" / "_shared"
LANES = 8
SESSIONS = 3
BODY_SIZE = 2 << 20
GREETING = b"stripe-ready"


class CarrierRelay:
    """Forward valid stripe frames while controlling order across TCP lanes."""

    def __init__(self, *, framed=True):
        self.framed = framed

    def __enter__(self):
        self.listener = socket.socket()
        configure_listener(self.listener, (HOST, RELAY_PORT), timeout=0.2)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.connections = []
        self.threads = []
        self.errors = []
        self.gates = {}
        self.acceptor = threading.Thread(target=self.accept, name="stripe-relay")
        self.acceptor.start()
        return self

    def accept(self):
        try:
            while not self.stop.is_set():
                try:
                    incoming = self.listener.accept()[0]
                except socket.timeout:
                    continue
                try:
                    outgoing = socket.create_connection((HOST, WIRE_PORT), timeout=1)
                except BaseException:
                    incoming.close()
                    raise
                for connection in (incoming, outgoing):
                    connection.settimeout(15)
                    connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                member = {"sockets": (incoming, outgoing), "session": None, "index": None,
                          "bytes": [0, 0], "dropped": False}
                with self.lock:
                    self.connections.append(member)
                for direction in (0, 1):
                    thread = threading.Thread(target=self.forward, args=(member, direction))
                    self.threads.append(thread)
                    thread.start()
        except BaseException as error:
            if not self.stop.is_set():
                self.errors.append(error)

    def forward(self, member, direction):
        source = member["sockets"][direction]
        target = member["sockets"][1 - direction]
        try:
            if not self.framed:
                while not self.stop.is_set():
                    payload = source.recv(65536)
                    if not payload:
                        raise EOFError
                    target.sendall(payload)
                    member["bytes"][direction] += len(payload)
                return
            while not self.stop.is_set():
                header = exact(source, 24, eof_error=EOFError)
                kind, reserved, length, offset, _auxiliary = struct.unpack("!B3sIQQ", header)
                assert reserved == b"\0\0\0" and 0 <= length <= 16384, "invalid stripe frame header"
                payload = exact(source, length, eof_error=EOFError)
                if kind == 1:
                    assert direction == 0 and length == 24, "invalid stripe introduction"
                    index, count, _window = struct.unpack("!HHI", payload[16:])
                    assert count == LANES and index < count, "unexpected lane identity"
                    with self.lock:
                        member["session"], member["index"] = payload[:16], index
                gate = self.gates.get((member["session"], direction))
                hold = gate is not None and kind == 3 and not gate["held"].is_set() and (
                    (gate["mode"] == "reorder" and offset == gate["offset"]) or
                    (gate["mode"] == "close" and member["index"] == 1))
                if hold:
                    gate["held"].set()
                    assert gate["release"].wait(10), "another lane never overtook the held DATA frame"
                    if self.stop.is_set():
                        return
                target.sendall(header + payload)
                if kind == 3:
                    member["bytes"][direction] += length
                if gate is not None:
                    later_data = gate["mode"] == "reorder" and kind == 3 and offset > gate["offset"]
                    close = gate["mode"] == "close" and kind == 5
                    if later_data or close:
                        gate["release"].set()
        except (EOFError, ConnectionResetError, BrokenPipeError):
            with contextlib.suppress(OSError):
                target.shutdown(socket.SHUT_WR)
        except BaseException as error:
            if not self.stop.is_set() and not member["dropped"]:
                self.errors.append(error)

    def session(self, number):
        with self.lock:
            assert len(self.connections) == number * LANES, "application did not create exactly eight carriers"
            members = self.connections[(number - 1) * LANES:number * LANES]
            identifiers = {member["session"] for member in members}
            assert len(identifiers) == 1 and None not in identifiers, "carrier session IDs differ"
            assert {member["index"] for member in members} == set(range(LANES)), "missing or duplicate lane index"
            return members[0]["session"]

    def arm(self, session, direction, mode, offset=0):
        self.gates[(session, direction)] = {"mode": mode, "offset": offset,
                                            "held": threading.Event(), "release": threading.Event()}

    def assert_exercised(self):
        assert not self.errors, self.errors
        for gate in self.gates.values():
            assert gate["held"].is_set() and gate["release"].is_set(), "cross-lane frame order was not exercised"

    def drop_member(self, session):
        member = next(member for member in self.connections if member["session"] == session and member["index"] == 3)
        member["dropped"] = True
        for connection in member["sockets"]:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)

    def __exit__(self, exc_type, exc, traceback):
        self.stop.set()
        for gate in self.gates.values():
            gate["release"].set()
        self.acceptor.join(timeout=2)
        self.listener.close()
        for member in self.connections:
            for connection in member["sockets"]:
                with contextlib.suppress(OSError):
                    connection.shutdown(socket.SHUT_RDWR)
        deadline = time.monotonic() + 5
        for thread in self.threads:
            thread.join(timeout=max(0, deadline - time.monotonic()))
        for member in self.connections:
            for connection in member["sockets"]:
                connection.close()
        assert not self.acceptor.is_alive() and all(not thread.is_alive() for thread in self.threads), \
            "stripe relay did not settle"
        if exc_type is None:
            self.assert_exercised()


def topology(carrier, *, relay=False, mux=False):
    nodes = [
        {"name": "application", "type": "TcpListener", "next": "mux-client" if mux else "stripe-client",
         "settings": {"address": HOST, "port": APP_PORT, "nodelay": True}},
        {"name": "stripe-client", "type": "ConnectionStripeClient", "next": "carrier-client",
         "settings": {"connections": LANES}},
    ]
    if mux:
        nodes += [
            {"name": "mux-client", "type": "MuxClient", "next": "stripe-client",
             "settings": {"mode": "fixed-connections-count", "per-worker-connections-count": 1}},
            {"name": "mux-server", "type": "MuxServer", "next": "backend", "settings": {}},
        ]
    if carrier == "kcp":
        nodes += [
            {"name": "carrier-client", "type": "KcpClient", "next": "wire-out", "settings": {}},
            {"name": "wire-out", "type": "UdpConnector",
             "settings": {"address": HOST, "port": WIRE_PORT, "balance-mode": "packet"}},
            {"name": "wire-in", "type": "UdpListener", "next": "carrier-server",
             "settings": {"address": HOST, "port": WIRE_PORT}},
            {"name": "carrier-server", "type": "KcpServer", "next": "stripe-server", "settings": {}},
        ]
    else:
        if carrier == "tls":
            nodes += [
                {"name": "carrier-client", "type": "TlsClient", "next": "wire-out",
                 "settings": {"sni": "tls.integration.test", "verify": False, "alpns": ["http/1.1"]}},
                {"name": "carrier-server", "type": "TlsServer", "next": "stripe-server",
                 "settings": {"cert-file": "server.crt", "key-file": "server.key",
                              "sni": "tls.integration.test"}},
            ]
        nodes += [
            {"name": "wire-out" if carrier == "tls" else "carrier-client", "type": "TcpConnector",
             "settings": {"address": HOST, "port": RELAY_PORT if relay else WIRE_PORT,
                          "nodelay": True, "fastopen": False}},
            {"name": "wire-in", "type": "TcpListener",
             "next": "carrier-server" if carrier == "tls" else "stripe-server",
             "settings": {"address": HOST, "port": WIRE_PORT, "nodelay": True}},
        ]
    nodes += [
        {"name": "stripe-server", "type": "ConnectionStripeServer", "next": "mux-server" if mux else "backend",
         "settings": {"max-connections": LANES, **({"setup-timeout-ms": 100} if relay and not mux else {})}},
        {"name": "backend", "type": "TcpConnector",
         "settings": {"address": HOST, "port": BACKEND_PORT, "nodelay": True, "fastopen": False}},
    ]
    return nodes


def body(identifier, direction, size=BODY_SIZE):
    pattern = bytes((value * 31 + identifier * 17 + direction * 73) % 256 for value in range(256))
    return (pattern * ((size + 255) // 256))[:size]


def fragmented_send(connection, payload):
    for offset in range(0, len(payload), 10007):
        connection.sendall(payload[offset:offset + 10007])


def exchange(connection, identifier, *, server, close=True):
    """Keep both directions busy beyond one receive window without echoing data."""
    with (connection if close else contextlib.nullcontext()):
        connection.settimeout(15)
        outgoing = body(identifier, int(server))
        expected = body(identifier, int(not server))
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as sender, close_on_error(connection):
            send = sender.submit(fragmented_send, connection, outgoing)
            received = exact(connection, len(expected), max_chunk=8191)
            assert received == expected, f"session {identifier}: {'upload' if server else 'download'} corrupted"
            send.result(timeout=15)
        if server:
            assert exact(connection, 4) == b"done", "client completion marker changed"
            connection.sendall(b"done")
            if close and identifier == 0:
                assert connection.recv(1) == b"", "backend did not observe client-first EOF"
            # When close is requested, other backends finish after their last response bytes.
        else:
            connection.sendall(b"done")
            assert exact(connection, 4) == b"done", "server completion marker changed"
            if not close:
                return
            if identifier == 0:
                connection.shutdown(socket.SHUT_RDWR)
            else:
                assert connection.recv(1) == b"", "response was not followed by server-first EOF"


def connect(process):
    return connect_when_ready(process, (HOST, APP_PORT), deadline=time.monotonic() + 10,
                             failure=lambda: AssertionError("stripe runtime exited before application connection"))


def open_session(process, backend, sockets, identifier):
    client = sockets.enter_context(connect(process))
    client.settimeout(15)
    peer = sockets.enter_context(backend.accept()[0])
    peer.settimeout(15)
    # No application byte has been written: introductions must open the backend.
    greeting = GREETING + identifier.to_bytes(4, "big")
    peer.sendall(greeting)
    assert exact(client, len(greeting)) == greeting, "server-first greeting was lost or crossed sessions"
    return client, peer


def open_mux_child(process, backend, sockets, identifier):
    client = sockets.enter_context(connect(process))
    client.settimeout(15)
    # Mux submits Open with the first child payload, not with child Init.
    opening = b"mux-request-" + identifier.to_bytes(4, "big")
    client.sendall(opening)
    peer = sockets.enter_context(backend.accept()[0])
    peer.settimeout(15)
    assert exact(peer, len(opening)) == opening, "MUX child opening reached the wrong service connection"
    greeting = GREETING + identifier.to_bytes(4, "big")
    peer.sendall(greeting)
    assert exact(client, len(greeting)) == greeting, "MUX child reply reached the wrong application"
    return client, peer


def assert_no_extra_backend(backend):
    assert not select.select([backend], [], [], 0.05)[0], "unexpected extra service connection"


def shutdown_active(process, client, peer):
    client.sendall(b"live")
    assert exact(peer, 4) == b"live"
    peer.sendall(b"ready")
    assert exact(client, 5) == b"ready"
    process.send_signal(signal.SIGTERM)
    assert process.wait(timeout=10) == 128 + signal.SIGTERM, "stripe runtime shutdown failed"
    assert client.recv(1) == b"", "application owner survived shutdown"
    assert peer.recv(1) == b"", "backend owner survived shutdown"


def relay_close(process, backend, relay, number, direction):
    with contextlib.ExitStack() as sockets:
        client, peer = open_session(process, backend, sockets, number)
        session = relay.session(number)
        relay.arm(session, direction, "close")
        source, target = (client, peer) if direction == 0 else (peer, client)
        payload = body(number, direction, 100 * 1024)
        source.sendall(payload)
        source.shutdown(socket.SHUT_RDWR)
        assert exact(target, len(payload)) == payload, "CLOSE overtaking DATA truncated the stream"
        assert target.recv(1) == b"", "final offset was not followed by EOF"
        relay.assert_exercised()
        process.check_running("stripe runtime failed while draining CLOSE")
        assert_no_extra_backend(backend)


def relay_failure(process, backend, relay, number):
    with contextlib.ExitStack() as sockets:
        client, peer = open_session(process, backend, sockets, number)
        session = relay.session(number)
        relay.drop_member(session)
        for connection in (client, peer):
            try:
                assert connection.recv(1) == b"", "losing one carrier left the application alive"
            except ConnectionResetError:
                pass
        process.check_running("one failed stripe session terminated the runtime")
        assert_no_extra_backend(backend)


def setup_expiry(process, backend):
    # The existing idle-table sweep is coarser than the configured deadline;
    # require bounded eventual EOF without asserting a precise elapsed time.
    incomplete_group = (struct.pack("!B3sIQQ", 1, b"\0\0\0", 24, 0, 0) +
                        b"unpaired-session" + struct.pack("!HHI", 0, LANES, 1 << 20))
    for introduction in (b"\x01\x00", incomplete_group):
        with socket.create_connection((HOST, WIRE_PORT), timeout=3) as connection:
            connection.settimeout(3)
            connection.sendall(introduction)
            assert connection.recv(1) == b"", "incomplete stripe setup did not expire"
        process.check_running("expiring incomplete stripe setup terminated the runtime")
        assert_no_extra_backend(backend)


def write_configuration(root, carrier, *, relay=False, mux=False, splice=True):
    for name in ("server.crt", "server.key"):
        shutil.copyfile(CERTIFICATES / name, root / name)
    (root / "config.json").write_text(json.dumps({"name": "connection-stripe", "nodes": topology(carrier, relay=relay, mux=mux)}))
    (root / "core.json").write_text(json.dumps(core_config(workers=1 if mux else 4, ram_profile="minimal", splice=splice)))


def runtime_command(binary, root, trace):
    if not trace:
        return [binary]
    tracer = shutil.which("strace")
    if tracer is None:
        raise RuntimeError("inconclusive: strace is required for Stripe splice evidence")
    return [tracer, "-D", "-f", "-yy", "-e", "trace=splice", "-o", str(root / "splice.log"), binary]


def trace_boundary(root, trace):
    return len((root / "splice.log").read_text()) if trace else 0


def check_trace(root, boundary, *, enabled, carrier):
    calls = list(successful_calls((root / "splice.log").read_text()[boundary:]))
    if not enabled or carrier != "tcp":
        assert not calls, "splice I/O occurred on a disabled or TLS/KCP-blocked chain"
        return
    outputs = [call for call in calls if re.match(r"splice\(\d+<pipe:\[\d+\]>, NULL, \d+<TCP:", call)]
    for label, endpoint in (("client upload", f"->{HOST}:{RELAY_PORT}"),
                            ("server upload", f"->{HOST}:{BACKEND_PORT}"),
                            ("server download", f"{HOST}:{WIRE_PORT}->"),
                            ("client download", f"{HOST}:{APP_PORT}->")):
        assert any(endpoint in call for call in outputs), \
            f"{label}: no successful post-setup pipe-to-socket DATA output (pipe prerequisites may be unavailable)"


def run_mux(binary, carrier, *, enabled=True, trace=False):
    with RunDirectory(f"waterwall-connection-stripe-mux-{carrier}-") as root:
        write_configuration(root, carrier, relay=True, mux=True, splice=enabled)
        with socket.socket() as backend:
            configure_listener(backend, (HOST, BACKEND_PORT), timeout=15)
            with Process(runtime_command(binary, root, trace), cwd=root, log_path=root / "stdout.log") as process, \
                    CarrierRelay(framed=carrier == "tcp") as relay, \
                    contextlib.ExitStack() as sockets, \
                    concurrent.futures.ThreadPoolExecutor(max_workers=SESSIONS * 2) as executor:
                children = [open_mux_child(process, backend, sockets, i) for i in range(SESSIONS)]
                assert len(relay.connections) == LANES, "MUX children did not share eight carriers"
                session = relay.session(1) if carrier == "tcp" else None
                assert_no_extra_backend(backend)
                boundary = trace_boundary(root, trace)
                jobs = []
                for identifier, (client, peer) in enumerate(children):
                    jobs += [executor.submit(exchange, client, identifier, server=False, close=False),
                             executor.submit(exchange, peer, identifier, server=True, close=False)]
                for job in jobs:
                    job.result(timeout=25)

                # Full close in each direction must finish only that Mux child.
                children[0][0].shutdown(socket.SHUT_RDWR)
                assert children[0][1].recv(1) == b"", "client child close did not reach its service"
                children[1][1].shutdown(socket.SHUT_RDWR)
                assert children[1][0].recv(1) == b"", "service child close did not reach its application"
                survivor, service = children[2]
                survivor.sendall(b"sibling-survived")
                assert exact(service, 16) == b"sibling-survived", "closing a child interrupted its sibling"
                service.sendall(b"reply-survived")
                assert exact(survivor, 14) == b"reply-survived", "closing a child interrupted reverse traffic"

                later = open_mux_child(process, backend, sockets, SESSIONS)
                jobs = []
                for identifier, (client, peer) in enumerate((children[2], later), start=SESSIONS):
                    jobs += [executor.submit(exchange, client, identifier, server=False, close=False),
                             executor.submit(exchange, peer, identifier, server=True, close=False)]
                for job in jobs:
                    job.result(timeout=25)
                # The list is append-only: replacing a group also fails this check.
                assert len(relay.connections) == LANES, "later child opened a new Stripe group"
                if carrier == "tcp":
                    assert relay.session(1) == session, "the shared Stripe group changed"
                assert all(min(member["bytes"]) > 16384 for member in relay.connections), \
                    "a shared carrier did not carry bidirectional traffic"
                relay.assert_exercised()
                assert_no_extra_backend(backend)
                shutdown_active(process, survivor, service)
                assert later[0].recv(1) == b"" and later[1].recv(1) == b"", "a Mux child survived shutdown"
        if trace:
            check_trace(root, boundary, enabled=enabled, carrier=carrier)
    print(f"ConnectionStripe Mux {carrier}: shared eight-carrier group, full-duplex children, independent close, reuse and shutdown passed")


def run(binary, carrier, *, enabled=True, trace=False):
    with RunDirectory(f"waterwall-connection-stripe-{carrier}-") as root:
        write_configuration(root, carrier, relay=carrier == "tcp", splice=enabled)
        with socket.socket() as backend:
            configure_listener(backend, (HOST, BACKEND_PORT), timeout=15)
            with Process(runtime_command(binary, root, trace), cwd=root, log_path=root / "stdout.log") as process, \
                    (CarrierRelay() if carrier == "tcp" else contextlib.nullcontext()) as relay:
                with concurrent.futures.ThreadPoolExecutor(max_workers=SESSIONS * 2) as executor, \
                        contextlib.ExitStack() as sockets:
                    sessions = [open_session(process, backend, sockets, identifier) for identifier in range(SESSIONS)]
                    if relay is not None:
                        assert len(relay.connections) == SESSIONS * LANES, "wrong aggregate carrier count"
                        for identifier in range(SESSIONS):
                            members = relay.connections[identifier * LANES:(identifier + 1) * LANES]
                            session = members[0]["session"]
                            assert {member["index"] for member in members} == set(range(LANES))
                            assert {member["session"] for member in members} == {session}
                            relay.arm(session, 0, "reorder", 0)
                            relay.arm(session, 1, "reorder", len(GREETING) + 4)
                    assert_no_extra_backend(backend)
                    boundary = trace_boundary(root, trace)
                    jobs = []
                    for identifier, (client, peer) in enumerate(sessions):
                        jobs += [executor.submit(exchange, client, identifier, server=False),
                                 executor.submit(exchange, peer, identifier, server=True)]
                    for job in jobs:
                        job.result(timeout=25)
                process.check_running("stripe runtime failed after concurrent session retirement")
                assert_no_extra_backend(backend)
                final_number = SESSIONS + 1
                if relay is not None:
                    relay.assert_exercised()
                    assert all(min(member["bytes"]) > 16384 for member in relay.connections), \
                        "a carrier did not carry application data in both directions"
                    setup_expiry(process, backend)
                    relay_close(process, backend, relay, SESSIONS + 1, 0)
                    relay_close(process, backend, relay, SESSIONS + 2, 1)
                    relay_failure(process, backend, relay, SESSIONS + 3)
                    final_number = SESSIONS + 4
                with contextlib.ExitStack() as sockets:
                    client, peer = open_session(process, backend, sockets, final_number)
                    if relay is not None:
                        relay.session(final_number)
                    assert_no_extra_backend(backend)
                    shutdown_active(process, client, peer)
        if trace:
            check_trace(root, boundary, enabled=enabled, carrier=carrier)
    detail = ", reordered DATA/CLOSE and member loss" if carrier == "tcp" else ""
    print(f"ConnectionStripe {carrier}: eight carriers, concurrent full-duplex streams, server-first, EOF{detail} and shutdown passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("carrier", choices=("tcp", "tls", "kcp"))
    parser.add_argument("--mux", action="store_true", help="verify Mux children sharing one striped TCP/TLS group")
    parser.add_argument("--splice", choices=("true", "false"), default="true")
    parser.add_argument("--trace-splice", action="store_true", help="require post-setup syscall evidence")
    args = parser.parse_args()
    if args.mux and args.carrier == "kcp":
        parser.error("--mux covers TCP and TLS carriers")
    install_termination_handler()
    (run_mux if args.mux else run)(str(Path(args.binary).resolve()), args.carrier,
                                 enabled=args.splice == "true", trace=args.trace_splice)
