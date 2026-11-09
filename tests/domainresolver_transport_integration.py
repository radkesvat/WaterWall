#!/usr/bin/env python3
"""Resolver modes against loopback DNS, including TCP fallback and private TLS/VLESS.

Run only through the namespace harness. Core DNS points at an independent counter:
explicit line modes must never use it. This tests the actual runtime and connectors;
native units cover synchronous callback and storage failure paths.
"""
import concurrent.futures
from contextlib import ExitStack
import json
import os
from pathlib import Path
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
from wwtest.process import Process, install_termination_handler
from wwtest.run_directory import RunDirectory
from wwtest.sockets import connect_when_ready, exact

HOST = "127.0.0.1"
DIRECT_SOURCE, VPN_SOURCE, VPN_SERVICE_HOST = "127.0.0.2", "127.0.0.3", "127.0.0.4"
APP, DNS, NATIVE, SERVICE, VPN = 26740, 26741, 26742, 26743, 26744
UUID = "5783a3e7-e373-51cd-8642-c83782b807c5"


def node(name, kind, settings, next_node=None):
    result = {"name": name, "type": kind, "settings": settings}
    if next_node is not None:
        result["next"] = next_node
    return result


def connector(name, kind="TcpUdpConnector"):
    return node(name, kind, {"address": "dest_context->address", "port": "dest_context->port",
                             "fastopen": False, "nodelay": True})


class DnsFixture:
    def __init__(self, stack, host, port, answer=HOST, spoof=True, answers=None):
        self.host, self.port, self.answer = host, port, answer
        self.answers = answers or {}
        self.spoof = spoof
        self.counts = {"udp": 0, "tcp": 0}
        self.names = {}
        self.sources = {}
        self.lock = threading.Lock()
        self.release_abandoned = threading.Event()
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        self.udp = stack.enter_context(socket.socket(family, socket.SOCK_DGRAM))
        self.tcp = stack.enter_context(socket.socket(family))
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.udp.bind((host, port))
        self.tcp.bind((host, port))
        self.tcp.listen()
        self.start(self.serve_udp)
        self.start(self.serve_tcp)

    @staticmethod
    def start(callback, *args):
        threading.Thread(target=callback, args=args, daemon=True).start()

    def response(self, query, network, peer):
        position, labels = 12, []
        while query[position]:
            length = query[position]
            labels.append(query[position + 1:position + 1 + length].decode())
            position += length + 1
        name = ".".join(labels)
        question = query[12:position + 5]
        with self.lock:
            self.counts[network] += 1
            count = self.names[name, network] = self.names.get((name, network), 0) + 1
            self.sources.setdefault((name, network), set()).add(peer[0])
        if name.startswith("pending") or name.startswith("timeout"):
            return None
        if name.startswith("retry") and count == 1:
            return None
        if name.startswith("abandon"):
            self.release_abandoned.wait(timeout=3)
        if name.startswith("slow"):
            time.sleep(.15)
        truncated = network == "udp" and name.startswith("tcp")
        absent = name.startswith("absent")
        is_a = question[-4:-2] == b"\x00\x01"
        answer = (b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x1e\x00\x04" +
                  socket.inet_aton(self.answers.get(name, self.answer))) if is_a and not (truncated or absent) else b""
        flags = 0x8380 if truncated else 0x8183 if absent else 0x8180
        return query[:2] + struct.pack(">HHHHH", flags, 1, bool(answer), 0, 0) + question + answer

    def udp_reply(self, query, peer):
        reply = self.response(query, "udp", peer)
        if reply is None:
            return
        try:
            if b"malformed" in query:
                self.udp.sendto(query[:2] + b"\x81", peer)
                return
            # A matching ID from a different source port must not be admitted.
            if self.spoof and b"wrong-peer" in query:
                family = socket.AF_INET6 if ":" in self.host else socket.AF_INET
                with socket.socket(family, socket.SOCK_DGRAM) as wrong:
                    wrong.bind((self.host, 0))
                    wrong.sendto(reply[:-4] + socket.inet_aton("127.0.0.2"), peer)
                time.sleep(.05)
            self.udp.sendto(reply, peer)
        except OSError:
            pass  # Fixture teardown may close a socket with a delayed answer pending.

    def serve_udp(self):
        while True:
            try:
                query, peer = self.udp.recvfrom(65536)
            except OSError:
                return
            self.start(self.udp_reply, query, peer)

    def tcp_peer(self, peer):
        with peer:
            peer.settimeout(5)
            try:
                while True:
                    length = struct.unpack(">H", exact(peer, 2))[0]
                    reply = self.response(exact(peer, length), "tcp", peer.getpeername())
                    if reply is not None:
                        wire = struct.pack(">H", len(reply)) + reply
                        # Split the length prefix and DNS body across ordinary reads.
                        for offset in range(0, len(wire), 3):
                            peer.sendall(wire[offset:offset + 3])
                            time.sleep(.001)
            except (AssertionError, OSError, EOFError):
                return

    def serve_tcp(self):
        while True:
            try:
                peer, _ = self.tcp.accept()
            except OSError:
                return
            self.start(self.tcp_peer, peer)


def serve_echo(listener, observed_sources=None):
    def echo(peer):
        with peer:
            try:
                while data := peer.recv(65536):
                    peer.sendall(data)
            except OSError:
                pass
    while True:
        try:
            peer, address = listener.accept()
        except OSError:
            return
        if observed_sources is not None:
            observed_sources.append(address[0])
        DnsFixture.start(echo, peer)


def request(process, name, port=APP):
    peer = connect_when_ready(process, (HOST, port), deadline=time.monotonic() + 8,
                              failure=lambda: AssertionError("resolver runtime exited"))
    try:
        peer.settimeout(8)
        peer.sendall(b"\x05\x01\x00")
        assert exact(peer, 2) == b"\x05\x00"
        encoded = name.encode()
        peer.sendall(b"\x05\x01\x00\x03" + bytes([len(encoded)]) + encoded + struct.pack(">H", SERVICE))
        return peer
    except BaseException:
        peer.close()
        raise


def roundtrip(process, name, port=APP):
    with request(process, name, port) as peer:
        complete_roundtrip(peer, name)


def complete_roundtrip(peer, name):
    assert exact(peer, 10)[:2] == b"\x05\x00", f"CONNECT failed for {name}"
    body = (name + "|ordered application data").encode() * 100
    peer.sendall(body)
    assert exact(peer, len(body)) == body, f"echo mismatch for {name}"


def wait_query(fixture, name):
    deadline = time.monotonic() + 3
    while (name, "udp") not in fixture.names:
        assert time.monotonic() < deadline, f"DNS fixture did not receive {name}"
        time.sleep(.005)


def vless_nodes():
    return [node("dns-vless", "VlessClient", {"uuid": UUID, "address": "dest_context->address",
                 "port": "dest_context->port", "protocol": "dest_context->protocol",
                 "first-payload-timeout-ms": 0}, "tls-client"),
            node("tls-client", "TlsClient", {"sni": "tls.integration.test", "verify": False}, "vpn-out"),
            node("vpn-out", "TcpConnector", {"address": HOST, "port": VPN, "fastopen": False}),
            node("vpn-in", "TcpListener", {"address": HOST, "port": VPN}, "tls-server"),
            node("tls-server", "TlsServer", {"cert-file": "server.crt", "key-file": "server.key"}, "vless-server"),
            node("vless-server", "VlessServer", {"uuid": UUID, "connect": True, "udp": True}, "dns-out"),
            connector("dns-out")]


def config(mode, endpoint):
    settings = {"strategy": "only-ipv4"}
    if mode != "omitted":
        settings["mode"] = "native" if mode == "native" else "direct" if mode.startswith("direct") else "chain"
    if settings.get("mode") not in (None, "native"):
        settings["servers"] = [endpoint]
    nodes = [node("in", "TcpListener", {"address": HOST, "port": APP}, "socks"),
             node("socks", "Socks5Server", {"no-auth": True, "connect": True}, "resolve"),
             node("resolve", "DomainResolver", settings, "app-out"), connector("app-out", "TcpConnector")]
    if mode in ("shared", "shared-explicit"):
        if mode == "shared-explicit":
            settings["dns-next"] = "router"
        nodes[2]["next"] = "router"
        nodes += [node("router", "Router", {"rules": [{"resolver-dns": True, "target": "dns-out"}]}, "app-out"),
                  connector("dns-out")]
    elif mode == "chain-default":
        nodes[3] = connector("app-out")
    elif mode == "shared-vless":
        # Omitted dns-next shares the application Router. The DNS-origin rule
        # must precede the resolved-IP rule, since the DNS peer is also HOST.
        nodes[2]["next"] = "router"
        nodes[3]["settings"]["source-ip"] = DIRECT_SOURCE
        nodes += [node("router", "Router", {"rules": [
            {"resolver-dns": True, "target": "dns-vless"},
            {"destination-ip": HOST + "/32", "target": "app-out"}]}, "dns-vless")]
        nodes += vless_nodes()
        nodes[-1]["settings"]["source-ip"] = VPN_SOURCE
    elif mode in ("chain", "chain-sniff", "pinned", "rejected"):
        settings["dns-next"] = "dns-out"
        nodes += [node("dns-out", "BlackHole", {"mode": "active"}) if mode == "rejected" else connector("dns-out")]
        if mode == "pinned":
            nodes[-1]["settings"].update({"address": HOST, "port": NATIVE})
        elif mode == "chain-sniff":
            settings["dns-next"] = "dns-router"
            # DNS is fully classified by the first rule. The unrelated TLS
            # rule must not make TCP fallback wait for its own first payload.
            nodes += [node("dns-router", "Router", {"rules": [
                {"resolver-dns": True, "target": "dns-out"},
                {"protocol": "tls", "target": "dns-out"}]}, "dns-out")]
    elif mode in ("vless", "vless-pinned"):
        settings["dns-next"] = "dns-vless"
        nodes += vless_nodes()
        if mode == "vless-pinned":
            # The logical DNS target and UDP/TCP selection are authoritative;
            # the fixed outer VPN connector must still use its separate peer.
            nodes[4]["settings"].update({"address": HOST, "port": NATIVE, "protocol": "tcp"})
    return nodes


def main():
    binary, mode = sys.argv[1:]
    install_termination_handler()
    with RunDirectory("ww-resolver-transport-") as root, ExitStack() as stack:
        dns_host = "::1" if mode == "direct6" else HOST
        fixture = DnsFixture(stack, dns_host, DNS, answers={
            "vpn.test": VPN_SERVICE_HOST, "tcp-vpn.test": VPN_SERVICE_HOST} if mode == "shared-vless" else None)
        native = DnsFixture(stack, HOST, NATIVE, spoof=False)
        echo = stack.enter_context(socket.socket())
        echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        echo.bind((HOST, SERVICE))
        echo.listen()
        direct_sources, vpn_sources = [], []
        DnsFixture.start(serve_echo, echo, direct_sources)
        if mode == "shared-vless":
            vpn_echo = stack.enter_context(socket.socket())
            vpn_echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            vpn_echo.bind((VPN_SERVICE_HOST, SERVICE))
            vpn_echo.listen()
            DnsFixture.start(serve_echo, vpn_echo, vpn_sources)
        endpoint = f"[{dns_host}]:{DNS}" if ":" in dns_host else f"{dns_host}:{DNS}"
        nodes = config("direct" if mode == "isolation" else mode, endpoint)
        if mode == "isolation":
            second = DnsFixture(stack, HOST, DNS + 4, answer="127.0.0.2")
            echo2 = stack.enter_context(socket.socket())
            echo2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            echo2.bind(("127.0.0.2", SERVICE))
            echo2.listen()
            DnsFixture.start(serve_echo, echo2)
            other = config("direct", f"{HOST}:{DNS + 4}")
            for entry in other:
                entry["name"] += "-second"
                if "next" in entry:
                    entry["next"] += "-second"
            other[0]["settings"]["port"] = APP + 10
            nodes += other
        (root / "config.json").write_text(json.dumps({"name": "resolver-transport", "nodes": nodes}))
        (root / "core.json").write_text(json.dumps({**core_config(workers=1 if mode == "chain" else 2, splice=True), "dns": {
            "servers": [f"{HOST}:{NATIVE}"], "lookups": "b", "timeout-ms": 500,
            "max-timeout-ms": 1000, "tries": 3}}))
        if mode in ("vless", "vless-pinned", "shared-vless"):
            for name in ("server.crt", "server.key"):
                shutil.copyfile(Path(__file__).parent / "speedtests/_shared" / name, root / name)
        with Process([binary], cwd=root, log_path=root / "stdout.log", cleanup_signal=signal.SIGTERM) as process:
            if mode == "rejected":
                with request(process, "blocked.test") as peer:
                    try:
                        reply = peer.recv(10)
                    except ConnectionResetError:
                        reply = b""
                    assert len(reply) < 2 or reply[:2] != b"\x05\x00", "rejected route resolved"
                assert fixture.counts == native.counts == {"udp": 0, "tcp": 0}, "route rejection escaped"
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=8) == 128 + signal.SIGTERM
                return 0
            roundtrip(process, "udp.test")
            roundtrip(process, "tcp.test")
            if mode == "shared-vless":
                roundtrip(process, "vpn.test")
                roundtrip(process, "tcp-vpn.test")
            roundtrip(process, "retry.test")
            roundtrip(process, "wrong-peer.test")
            # Both queries are admitted before close; chain mode uses one worker
            # so this necessarily exercises a shared channel's cancellation boundary.
            expected = native if mode in ("omitted", "native") else fixture
            with request(process, "abandon.test") as abandoned:
                wait_query(expected, "abandon.test")
                with request(process, "slow-survivor.test") as survivor:
                    wait_query(expected, "slow-survivor.test")
                    abandoned.close()
                    expected.release_abandoned.set()
                    complete_roundtrip(survivor, "slow-survivor.test")
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
                list(executor.map(lambda index: roundtrip(process, f"slow-{index}.test"), range(12)))
            roundtrip(process, "udp.test")  # May complete from the per-instance cache.
            if mode == "isolation":
                roundtrip(process, "udp.test", APP + 10)
                roundtrip(process, "tcp.test", APP + 10)
                assert second.counts["udp"] > 0 and second.counts["tcp"] > 0, "resolver instances shared cache"
            for name in ("absent.test", "timeout.test", "malformed.test"):
                with request(process, name) as peer:
                    try:
                        reply = peer.recv(10)
                    except ConnectionResetError:
                        reply = b""
                    assert len(reply) < 2 or reply[:2] != b"\x05\x00", f"failed DNS escaped for {name}"
            assert expected.counts["udp"] > 0 and expected.counts["tcp"] > 0, expected.counts
            if expected is fixture:
                assert native.counts == {"udp": 0, "tcp": 0}, f"native DNS escape: {native.counts}"
            else:
                assert fixture.counts == {"udp": 0, "tcp": 0}, "native mode used explicit fixture"
            if mode == "shared-vless":
                assert direct_sources and set(direct_sources) == {DIRECT_SOURCE}, direct_sources
                assert len(vpn_sources) == 2 and set(vpn_sources) == {VPN_SOURCE}, vpn_sources
                for name, network in (("udp.test", "udp"), ("tcp.test", "udp"), ("tcp.test", "tcp"),
                                      ("vpn.test", "udp"), ("tcp-vpn.test", "udp"), ("tcp-vpn.test", "tcp")):
                    assert fixture.sources.get((name, network)) == {VPN_SOURCE}, (
                        f"{name}/{network} bypassed the VPN DNS branch: {fixture.sources}")
            # Keep an unanswered request alive across worker quiescence/drain.
            with request(process, "pending.test"):
                wait_query(expected, "pending.test")
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=8) == 128 + signal.SIGTERM, "resolver shutdown failed"
        print(f"{mode}: UDP/TCP, retry, wrong peer, concurrency, no escape and shutdown passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
