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
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.config import core_config
from wwtest.fixtures.http_proxy import header as http_header
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
        self.tcp_prefixes = []
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
                    prefix = exact(peer, 2)
                    self.tcp_prefixes.append(prefix)
                    length = struct.unpack(">H", prefix)[0]
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


def serve_dns_connect_proxy(listener, observed_headers):
    """An independent CONNECT peer forwards framed DNS only after proxy authentication."""
    def connection(peer):
        with peer:
            peer.settimeout(5)
            try:
                request_header = http_header(peer)
                observed_headers.append(request_header)
                expected = (f"CONNECT {HOST}:{DNS} HTTP/1.1\r\nHost: {HOST}:{DNS}\r\n"
                            "Proxy-Authorization: Basic Zml4dHVyZTpzZWNyZXQ=\r\n\r\n").encode()
                if request_header != expected:
                    return
                with socket.create_connection((HOST, DNS), timeout=5) as upstream:
                    peer.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    while True:
                        prefix = exact(peer, 2)
                        query = exact(peer, struct.unpack(">H", prefix)[0])
                        upstream.sendall(prefix + query)
                        prefix = exact(upstream, 2)
                        reply = exact(upstream, struct.unpack(">H", prefix)[0])
                        peer.sendall(prefix + reply)
            except (AssertionError, OSError):
                return
    while True:
        try:
            peer, _ = listener.accept()
        except OSError:
            return
        DnsFixture.start(connection, peer)


def request(process, name, port=APP, numeric=False):
    peer = connect_when_ready(process, (HOST, port), deadline=time.monotonic() + 8,
                              failure=lambda: AssertionError("resolver runtime exited"))
    try:
        peer.settimeout(8)
        peer.sendall(b"\x05\x01\x00")
        assert exact(peer, 2) == b"\x05\x00"
        address = b"\x01" + socket.inet_aton(name) if numeric else b"\x03" + bytes([len(name.encode())]) + name.encode()
        peer.sendall(b"\x05\x01\x00" + address + struct.pack(">H", SERVICE))
        return peer
    except BaseException:
        peer.close()
        raise


def roundtrip(process, name, port=APP, numeric=False):
    with request(process, name, port, numeric=numeric) as peer:
        complete_roundtrip(peer, name)


def complete_roundtrip(peer, name):
    assert exact(peer, 10)[:2] == b"\x05\x00", f"CONNECT failed for {name}"
    body = (name + "|ordered application data").encode() * 100
    peer.sendall(body)
    assert exact(peer, len(body)) == body, f"echo mismatch for {name}"


def udp_application(process, name, numeric=False):
    """A SOCKS UDP application uses the combined owner's UDP child/provider."""
    with connect_when_ready(process, (HOST, APP), deadline=time.monotonic() + 8,
                            failure=lambda: AssertionError("UDP application runtime exited")) as control:
        control.settimeout(5)
        control.sendall(b"\x05\x01\x00")
        assert exact(control, 2) == b"\x05\x00"
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        reply = exact(control, 10)
        assert reply[:4] == b"\x05\x00\x00\x01", "UDP association failed"
        relay = (socket.inet_ntoa(reply[4:8]), struct.unpack(">H", reply[8:10])[0])
        address = b"\x01" + socket.inet_aton(name) if numeric else b"\x03" + bytes([len(name)]) + name.encode()
        header = b"\x00\x00\x00" + address + struct.pack(">H", SERVICE)
        body = b"combined provider UDP application"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(.2)
            deadline = time.monotonic() + 5
            while True:
                client.sendto(header + body, relay)
                try:
                    received, _ = client.recvfrom(65536)
                    assert received[:4] == b"\x00\x00\x00\x01" and received[10:] == body, "UDP application echo changed"
                    return
                except TimeoutError:
                    assert time.monotonic() < deadline, "UDP application did not traverse combined provider"


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
    elif mode.startswith("http-pinned"):
        settings["dns-next"] = "dns-router"
        resolve = mode.endswith("-resolve")
        nodes += [node("dns-router", "Router", {"rules": [
            {"network": "udp", "target": "dns-udp"}]}, "dns-http"),
            connector("dns-udp", "UdpConnector"),
            node("dns-http", "HttpProxyClient", {
                "target-address": "must-not-resolve.test" if resolve else "dest_context->address",
                "port": NATIVE if resolve else "dest_context->port", "username": "fixture", "password": "secret",
                "dns-behaviour": {"resolve": resolve}}, "dns-proxy-out"),
            node("dns-proxy-out", "TcpConnector", {"address": HOST, "port": VPN, "fastopen": False})]
    elif mode == "ctp-pinned":
        settings["dns-next"] = "dns-ctp"
        nodes += [node("dns-ctp", "ConnectionToPackets", {
            "source-ipv4": "10.27.0.2", "target-address": HOST, "port": NATIVE,
            "dns-behaviour": {"resolve": False}}, "dns-ptc"),
            node("dns-ptc", "PacketsToConnection", {}, "dns-out"), connector("dns-out")]
    return nodes


def udp_balancing_config(mode, endpoint):
    policy = {"resolve": mode != "disabled"}
    if mode != "disabled":
        policy.update({"mode": mode, "strategy": "only-ipv4"})
        if mode != "native":
            policy["servers"] = [endpoint]
        if mode == "chain":
            policy["dns-next"] = "dns-out"
    settings = {"balance-mode": "packet", "dns-behaviour": policy,
                "addresses": [{"address": address, "port": SERVICE, "weight": 1}
                              for address in (HOST, "udp-balance.test", "tcp-balance.test")]}
    nodes = [node("in", "UdpListener", {"address": HOST, "port": APP}, "out"),
             node("out", "UdpConnector", settings)]
    if mode == "chain":
        nodes.append(connector("dns-out"))
    return nodes


def run_udp_balancing(binary, mode):
    """Initial and later weighted destinations share one selected DNS backend."""
    install_termination_handler()
    with RunDirectory("ww-udp-dns-policy-") as root, ExitStack() as stack:
        fixture = DnsFixture(stack, HOST, DNS)
        native = DnsFixture(stack, HOST, NATIVE, spoof=False)
        echo = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
        echo.bind((HOST, SERVICE))

        def serve_datagrams():
            while True:
                try:
                    data, peer = echo.recvfrom(65536)
                    echo.sendto(data, peer)
                except OSError:
                    return

        DnsFixture.start(serve_datagrams)
        (root / "config.json").write_text(json.dumps({"name": "udp-dns-policy", "nodes":
            udp_balancing_config(mode, f"{HOST}:{DNS}")}))
        (root / "core.json").write_text(json.dumps({**core_config(workers=2), "dns": {
            "servers": [f"{HOST}:{NATIVE}"], "lookups": "b", "timeout-ms": 500,
            "max-timeout-ms": 1000, "tries": 2}}))
        with Process([binary], cwd=root, log_path=root / "stdout.log",
                     cleanup_signal=signal.SIGTERM) as process:
            client = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            client.settimeout(.08)
            received = set()
            deadline = time.monotonic() + 10
            for index in range(128):
                process.check_running("UDP DNS policy runtime exited")
                body = f"datagram-{index}".encode()
                client.sendto(body, (HOST, APP))
                try:
                    reply, peer = client.recvfrom(65536)
                    assert peer == (HOST, APP) and reply.startswith(b"datagram-"), "UDP echo changed"
                    received.add(reply)
                except TimeoutError:
                    pass
                assert time.monotonic() < deadline, "UDP DNS policy did not make progress"
                expected = native if mode == "native" else fixture
                if len(received) >= 16 and (mode == "disabled" or all(
                        (name, network) in expected.names for name, network in
                        (("udp-balance.test", "udp"), ("tcp-balance.test", "udp"),
                         ("tcp-balance.test", "tcp")))):
                    break
            assert len(received) >= 16, "numeric UDP destinations stopped working"
            if mode == "disabled":
                assert fixture.counts == native.counts == {"udp": 0, "tcp": 0}, "disabled UDP queried DNS"
            else:
                expected = native if mode == "native" else fixture
                assert all((name, network) in expected.names for name, network in
                           (("udp-balance.test", "udp"), ("tcp-balance.test", "udp"),
                            ("tcp-balance.test", "tcp"))), "later UDP destinations bypassed selected DNS policy"
                other = fixture if mode == "native" else native
                assert other.counts == {"udp": 0, "tcp": 0}, f"UDP DNS transport fallback: {other.counts}"
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=8) == 128 + signal.SIGTERM, "UDP DNS shutdown failed"
    print(f"UDP packet balancing {mode}: initial/later DNS, TCP fallback, numeric destinations and no escape passed")
    return 0


def embedded_config(kind, mode, endpoint):
    """Exercise the same real DNS transport through a consumer-owned provider."""
    policy = {"resolve": mode != "disabled"}
    if mode != "disabled":
        policy.update({"mode": mode, "strategy": "only-ipv4"})
        if mode != "native":
            policy["servers"] = [endpoint]
    nodes = config("omitted", endpoint)
    nodes.pop(2)  # Resolution belongs to the consumer under test.
    nodes[1]["next"] = "consumer"
    if kind in ("tcp", "combined"):
        nodes[2]["name"] = "consumer"
        nodes[2]["type"] = "TcpConnector" if kind == "tcp" else "TcpUdpConnector"
        owner = nodes[2]
        if kind == "combined":
            nodes[0]["type"] = "TcpUdpListener"
            nodes[1]["settings"].update({"udp": True, "ipv4": HOST})
    elif kind == "router":
        settings = {"rules": [{"resolver-dns": True, "target": "dns-out"}]} if mode == "chain" else {}
        owner = node("consumer", "Router", settings, "app-out")
        nodes.append(owner)
        if mode == "chain":
            nodes.append(connector("dns-out"))
    elif kind == "ctp":
        owner = node("consumer", "ConnectionToPackets", {"source-ipv4": "10.27.0.2"}, "ptc")
        nodes += [owner, node("ptc", "PacketsToConnection", {}, "app-out")]
    else:
        # The peer must carry both DNS datagrams and TCP fallback.
        nodes[2] = connector("app-out")
        # All logical proxy targets remain separate from their numeric outer peer.
        peer_kind = {"vless": "Vless", "vmess": "Vmess", "trojan": "Trojan", "socks": "Socks5", "http": "HttpProxy"}[kind]
        settings = {"target-address": "dest_context->address", "port": "dest_context->port"}
        server_settings = {"connect": True, "udp": True}
        if kind in ("vless", "vmess"):
            settings["uuid"] = server_settings["uuid"] = UUID
        elif kind == "trojan":
            settings["password"] = server_settings["password"] = "dns-test-password"
        elif kind == "socks":
            server_settings.update({"no-auth": True, "ipv4": HOST})
        elif kind == "http":
            server_settings = {"no-auth": True}
        if kind != "http":
            settings["protocol"] = "dest_context->protocol"
        owner = node("consumer", peer_kind + "Client", settings, "vpn-out")
        nodes += [owner, node("vpn-out", "TcpConnector", {"address": HOST, "port": VPN, "fastopen": False}),
                  node("vpn-in", "TcpListener", {"address": HOST, "port": VPN}, "proxy-server"),
                  node("proxy-server", peer_kind + "Server", server_settings, "app-out")]
        if kind == "socks":
            nodes[-2]["type"] = "TcpUdpListener"
            nodes[-3]["type"] = "TcpUdpConnector"
    if mode == "chain" and kind in ("tcp", "combined", "ctp", "http"):
        policy["dns-next"] = "dns-out"
        nodes.append(connector("dns-out"))
    owner["settings"]["dns-behaviour"] = policy
    if mode == "disabled":
        for entry in nodes:
            if entry["name"] == "app-out":
                entry["settings"]["dns-behaviour"] = {"resolve": False}
    return nodes


def main():
    binary, mode = sys.argv[1:]
    if mode.startswith("udp-balancing-"):
        return run_udp_balancing(binary, mode.removeprefix("udp-balancing-"))
    embedded = mode.split("-") if mode.startswith("embedded-") else None
    if embedded:
        _, consumer, mode = embedded
    install_termination_handler()
    with RunDirectory("ww-resolver-transport-") as root, ExitStack() as stack:
        dns_host = "::1" if mode == "direct6" else HOST
        if mode == "ctp-pinned":
            # The virtual lwIP stack keeps 127/8 local instead of emitting it
            # through CTP. Keep the real fixture on this namespace's loopback.
            parent_netns = os.environ.get("WATERWALL_TEST_PARENT_NETNS")
            assert parent_netns and os.readlink("/proc/self/ns/net") != parent_netns, \
                "CTP DNS test requires the private network namespace wrapper"
            dns_host = "10.27.0.53"
            subprocess.run(["ip", "address", "add", dns_host + "/32", "dev", "lo"], check=True, timeout=5)
            stack.callback(subprocess.run, ["ip", "address", "del", dns_host + "/32", "dev", "lo"],
                           check=True, timeout=5)
        fixture = DnsFixture(stack, dns_host, DNS, answers={
            "vpn.test": VPN_SERVICE_HOST, "tcp-vpn.test": VPN_SERVICE_HOST} if mode == "shared-vless" else None)
        native = DnsFixture(stack, HOST, NATIVE, spoof=False)
        proxy_headers = []
        if mode.startswith("http-pinned"):
            proxy = stack.enter_context(socket.socket())
            proxy.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            proxy.bind((HOST, VPN))
            proxy.listen()
            DnsFixture.start(serve_dns_connect_proxy, proxy, proxy_headers)
        echo = stack.enter_context(socket.socket())
        echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        echo.bind((HOST, SERVICE))
        echo.listen()
        direct_sources, vpn_sources = [], []
        DnsFixture.start(serve_echo, echo, direct_sources)
        if embedded and consumer == "combined":
            udp_echo = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_DGRAM))
            udp_echo.bind((HOST, SERVICE))

            def serve_application_datagrams():
                while True:
                    try:
                        data, peer = udp_echo.recvfrom(65536)
                        udp_echo.sendto(data, peer)
                    except OSError:
                        return

            DnsFixture.start(serve_application_datagrams)
        if mode == "shared-vless":
            vpn_echo = stack.enter_context(socket.socket())
            vpn_echo.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            vpn_echo.bind((VPN_SERVICE_HOST, SERVICE))
            vpn_echo.listen()
            DnsFixture.start(serve_echo, vpn_echo, vpn_sources)
        endpoint = f"[{dns_host}]:{DNS}" if ":" in dns_host else f"{dns_host}:{DNS}"
        nodes = embedded_config(consumer, mode, endpoint) if embedded else config("direct" if mode == "isolation" else mode, endpoint)
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
            if embedded and mode == "disabled":
                roundtrip(process, HOST, numeric=True)
                with request(process, "disabled.test") as peer:
                    try:
                        reply = peer.recv(10)
                        if len(reply) >= 2 and reply[:2] == b"\x05\x00":
                            # Transport Est can precede a remote protocol's refusal.
                            peer.sendall(b"unresolved target must not be delivered")
                            assert peer.recv(4096) == b"", "unresolved destination carried application data"
                    except (ConnectionResetError, BrokenPipeError):
                        pass
                roundtrip(process, HOST, numeric=True)
                if consumer == "combined":
                    udp_application(process, HOST, numeric=True)
                assert fixture.counts == native.counts == {"udp": 0, "tcp": 0}, "disabled consumer queried DNS"
                process.send_signal(signal.SIGTERM)
                assert process.wait(timeout=8) == 128 + signal.SIGTERM, "disabled consumer shutdown failed"
                print(f"{consumer}: disabled lookup preserved numeric destinations and made no DNS queries")
                return 0
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
            if embedded and consumer == "combined":
                udp_application(process, "tcp-application.test")
                selected_dns = native if mode == "native" else fixture
                assert ("tcp-application.test", "udp") in selected_dns.names and ("tcp-application.test", "tcp") in selected_dns.names, "combined UDP application did not use its shared DNS policy"
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
            if mode.startswith("http-pinned"):
                assert proxy_headers, "TCP fallback bypassed its configured HTTP proxy"
                assert all(header.startswith(f"CONNECT {HOST}:{DNS} HTTP/1.1\r\n".encode()) and
                           b"Proxy-Authorization: Basic Zml4dHVyZTpzZWNyZXQ=\r\n" in header
                           for header in proxy_headers), "proxy received the wrong DNS authority or credentials"
                assert b"CO" not in fixture.tcp_prefixes, "HTTP CONNECT/credentials escaped to the DNS server"
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
