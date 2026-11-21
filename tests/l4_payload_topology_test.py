#!/usr/bin/env python3
"""Check direct L4 declarations and observe local transport choices on loopback."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import select
import signal
import socket
import sys
import time

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR", str(HERE / "support" / "python")))
from wwtest.config import core_config, STARTED_MARKER
from wwtest.process import Process, install_termination_handler
from wwtest.run_directory import RunDirectory
from wwtest.sockets import connect_when_ready, exact


def startup(binary, config, *, conflict=(), error_terms=(), quic=False, exercise=None):
    with RunDirectory("waterwall-l4-" + config["name"] + "-") as root:
        if quic:
            for filename in ("server.crt", "server.key"):
                shutil.copyfile(HERE / "speedtests" / "_shared" / filename, root / filename)
        (root / "core.json").write_text(json.dumps(core_config()))
        (root / "config.json").write_text(json.dumps(config))
        output_path = root / "stdout.log"
        with Process([binary], cwd=root, log_path=output_path) as process:
            deadline = time.monotonic() + 8
            while process.poll() is None and time.monotonic() < deadline:
                if STARTED_MARKER in output_path.read_text(errors="replace"):
                    assert not (conflict or error_terms), f"{config['name']}: invalid payload topology started"
                    if exercise:
                        exercise(process, deadline)
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=10) == 128 + signal.SIGTERM, config["name"]
                    return
                time.sleep(0.01)

            output = output_path.read_text(errors="replace")
            assert (conflict or error_terms) and process.poll() == 1 and STARTED_MARKER not in output, output
            required = (*conflict, "stream", "datagram") if conflict else error_terms
            assert any(all(term in line.lower() for term in required) for line in output.splitlines()), output


def quic_cases(binary):
    examples = HERE.parent / "tunnels" / "QuicClient" / "examples"
    for carrier in ("datagram", "stream"):
        for role in ("client", "server"):
            config = json.loads((examples / carrier / role / "config.json").read_text())
            startup(binary, config, quic=True)

    client = json.loads((examples / "datagram" / "client" / "config.json").read_text())
    server = json.loads((examples / "datagram" / "server" / "config.json").read_text())
    client["name"] = "quic-client-direct-tcp"
    client["nodes"][-1]["type"] = "TcpConnector"
    startup(binary, client, conflict=("quic", "carrier"), quic=True)
    server["name"] = "quic-server-direct-tcp"
    server["nodes"][0]["type"] = "TcpListener"
    startup(binary, server, conflict=("quic", "carrier"), quic=True)

    client["name"] = "quic-client-through-logger"
    client["nodes"][1]["next"] = "log"
    client["nodes"].append({"name": "log", "type": "LoggerTunnel", "settings": {"mode": "log"}, "next": "carrier"})
    startup(binary, client, quic=True)


def socket_node(name, kind, port, *, next_node=None):
    node = {"name": name, "type": kind, "settings": {"address": "127.0.0.1", "port": port}}
    if next_node is not None:
        node["next"] = next_node
    return node


def make_backends(stack_port):
    """Bind both kinds to the same endpoint so any wrong choice is observable."""
    tcp = socket.socket()
    udp = socket.socket(type=socket.SOCK_DGRAM)
    try:
        for sock in (tcp, udp):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("127.0.0.1", stack_port))
            sock.settimeout(5)
        tcp.listen()
        return tcp, udp
    except BaseException:
        tcp.close()
        udp.close()
        raise


def receive_packet(tcp, udp, expected):
    ready, _, _ = select.select([tcp, udp], [], [], 5)
    wanted = tcp if expected == "tcp" else udp
    assert ready == [wanted], f"expected {expected} backend only, got {ready}"
    if wanted == tcp:
        peer, _ = tcp.accept()
        with peer:
            peer.settimeout(5)
            prefix = exact(peer, 4)
            packet = prefix + exact(peer, int.from_bytes(prefix[2:4], "big") - len(prefix))
    else:
        packet, _ = udp.recvfrom(65535)
    assert packet[0] >> 4 == 4 and int.from_bytes(packet[2:4], "big") == len(packet)
    assert packet[9] == socket.IPPROTO_TCP, "the encapsulated IP protocol changed with the carrier"


def packet_producer(next_node, protocol=None):
    packet_input = {"name": "packets", "type": "TesterClient", "next": "bridge",
                    "settings": {"packet-mode": True, "chunk-count": 1,
                                 "packet-ipv4": {"transport": "tcp", "source-ip": "10.92.0.1",
                                                 "dest-ip": "10.92.0.2"}}}
    bridge = {"name": "bridge", "type": "PacketsToStream", "next": next_node}
    if protocol is not None:
        bridge["settings"] = {"protocol": protocol}
    return [packet_input, bridge]


def dispatch_cases(binary):
    ingress_port, backend_port = 29845, 29846
    for listener, connector in (("TcpListener", "UdpConnector"), ("UdpListener", "TcpConnector")):
        config = {"name": "fixed-mismatch-" + listener, "nodes": [
            socket_node("ingress", listener, ingress_port, next_node="egress"),
            socket_node("egress", connector, backend_port)]}
        startup(binary, config, conflict=("ingress", "egress", "next", "prev"))

    cases = (("TcpConnector", None, False, "tcp"),
             ("UdpConnector", None, False, "udp"),
             ("TcpUdpConnector", None, False, "tcp"),
             ("TcpUdpConnector", "udp", False, "udp"),
             ("UdpConnector", None, True, "udp"))
    for connector, protocol, logger, expected in cases:
        nodes = packet_producer("log" if logger else "egress", protocol)
        if logger:
            nodes.append({"name": "log", "type": "LoggerTunnel", "next": "egress", "settings": {"mode": "log"}})
        nodes.append(socket_node("egress", connector, backend_port))
        tcp, udp = make_backends(backend_port)
        with tcp, udp:
            startup(binary, {"name": f"dispatch-{connector}-{protocol}-{logger}", "nodes": nodes},
                    exercise=lambda process, deadline: receive_packet(tcp, udp, expected))

    nodes = packet_producer("egress", "udp") + [socket_node("egress", "TcpConnector", backend_port)]
    startup(binary, {"name": "restricted-producer-mismatch", "nodes": nodes},
            conflict=("bridge", "egress", "next", "prev"))

    nodes = packet_producer("egress", "invalid") + [socket_node("egress", "TcpConnector", backend_port)]
    startup(binary, {"name": "invalid-producer-protocol", "nodes": nodes},
            error_terms=("packetstostream", "protocol"))


def routing_cases(binary):
    ingress = ("127.0.0.1", 29845)
    tcp_port, udp_port = 29846, 29847
    stream = socket_node("stream", "TcpConnector", tcp_port)
    datagram = socket_node("datagram", "UdpConnector", udp_port)
    listener = socket_node("ingress", "TcpUdpListener", ingress[1], next_node="route")
    router = {"name": "route", "type": "Router", "next": "stream",
              "settings": {"rules": [{"network": "udp", "target": "datagram"},
                                     {"network": "tcp", "target": "stream"}]}}

    def exchange(process, deadline):
        with connect_when_ready(process, ingress, deadline=deadline, timeout=5,
                                failure=lambda: AssertionError("TCP ingress failed to bind")) as client:
            client.sendall(b"stream")
            peer, _ = tcp.accept()
            with peer:
                peer.settimeout(5)
                assert exact(peer, 6) == b"stream"
                peer.sendall(b"TCP")
                assert exact(client, 3) == b"TCP"
        with socket.socket(type=socket.SOCK_DGRAM) as client:
            client.settimeout(5)
            client.sendto(b"datagram", ingress)
            payload, peer = udp.recvfrom(1024)
            assert payload == b"datagram"
            udp.sendto(b"UDP", peer)
            assert client.recvfrom(1024)[0] == b"UDP"

    with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
        tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp.bind(("127.0.0.1", tcp_port))
        tcp.listen()
        tcp.settimeout(5)
        udp.bind(("127.0.0.1", udp_port))
        udp.settimeout(5)
        startup(binary, {"name": "exact-accepted-lines", "nodes": [listener, router, stream, datagram]},
                exercise=exchange)

    # A single adaptable producer lets rule order choose the transport. Both rules
    # have the same target so the choice must travel with the winning rule.
    cases = (("udp-first", [{"network": "udp"}, {"network": "tcp"}], "udp"),
             ("tcp-first", [{"network": "tcp"}, {"network": "udp"}], "tcp"),
             ("port-miss", [{"network": "udp", "destination-port": 12345}, {"network": "tcp"}], "tcp"),
             ("combined", [{"network": "tcp,udp"}], "tcp"),
             ("default", [{"network": "udp", "destination-port": 12345}], "tcp"))
    for name, rules, expected in cases:
        router["next"] = "egress"
        router["settings"]["rules"] = [dict(rule, target="egress") for rule in rules]
        nodes = [*packet_producer("route"), router, socket_node("egress", "TcpUdpConnector", tcp_port)]
        tcp, udp = make_backends(tcp_port)
        with tcp, udp:
            startup(binary, {"name": name, "nodes": nodes},
                    exercise=lambda process, deadline: receive_packet(tcp, udp, expected))


def socks_udp_ingress_cases(binary):
    listener = socket_node("ingress", "TcpUdpListener", 29845, next_node="route")
    socks = {"name": "socks", "type": "Socks5Server", "next": "egress",
             "settings": {"no-auth": True, "connect": False, "udp": True, "ipv4": "127.0.0.1"}}
    egress = socket_node("egress", "UdpConnector", 29846)
    router = {"name": "route", "type": "Router", "next": "socks",
              "settings": {"rules": [{"network": "udp", "target": "elsewhere"}]}}
    other = {"name": "elsewhere", "type": "BlackHole", "settings": {"mode": "passive"}}
    startup(binary, {"name": "udp-associate-relay-diverted", "nodes": [listener, router, socks, other, egress]})


def routing_context_cases(binary):
    ingress = ("127.0.0.1", 29845)
    fallback_port = 29846
    server = {"name": "proxy", "type": "HttpProxyServer", "next": "ordinary",
              "settings": {"users": [{"username": "fixture", "password": "fixture"}],
                           "fallback-node-name": "route"}}
    router = {"name": "route", "type": "Router", "next": "datagram",
              "settings": {"rules": [{"network": "tcp", "target": "fallback"}]}}
    nodes = [socket_node("ingress", "TcpListener", ingress[1], next_node="proxy"), server, router,
             socket_node("ordinary", "TcpConnector", 29847),
             socket_node("datagram", "UdpConnector", fallback_port),
             socket_node("fallback", "TcpConnector", fallback_port)]

    def exchange(process, deadline):
        request = (b"GET http://untrusted.invalid:19/a HTTP/1.1\r\nHost: unchanged\r\n"
                   b"Proxy-Authorization: Basic !!!\r\n\r\noriginal-tail")
        with connect_when_ready(process, ingress, deadline=deadline, timeout=5,
                                failure=lambda: AssertionError("HTTP ingress failed to bind")) as client:
            client.settimeout(5)
            client.sendall(request)
            ready, _, _ = select.select([tcp, udp], [], [], 5)
            assert ready == [tcp], "HTTP fallback must select its TCP branch"
            peer, _ = tcp.accept()
            with peer:
                peer.settimeout(5)
                assert exact(peer, len(request)) == request
                response = b"HTTP/1.1 204 No Content\r\n\r\n"
                peer.sendall(response)
                assert exact(client, len(response)) == response

    tcp, udp = make_backends(fallback_port)
    with tcp, udp:
        startup(binary, {"name": "http-fallback-exact-tcp", "nodes": nodes}, exercise=exchange)


def header_stream_case(binary):
    ingress = ("127.0.0.1", 29845)
    backend = ("127.0.0.1", 29846)
    nodes = [socket_node("in", "TcpListener", ingress[1], next_node="header"),
             {"name": "header", "type": "HeaderServer",
              "settings": {"override": "line-mark"}, "next": "decode"},
             {"name": "decode", "type": "UdpOverTcpServer", "next": "out"},
             socket_node("out", "UdpConnector", backend[1])]

    def exchange(process, deadline):
        with connect_when_ready(process, ingress, deadline=deadline, timeout=5,
                                failure=lambda: AssertionError("TCP carrier did not start")) as carrier:
            carrier.settimeout(5)
            # Fragment the mark, then complete it with one frame and half the next length.
            carrier.sendall(bytes(range(15)))
            carrier.sendall(b"\x0f\x00\x03one\x00")
            first, peer = udp.recvfrom(1024)
            assert first == b"one", first
            udp.sendto(b"ack", peer)
            assert exact(carrier, 5) == b"\x00\x03ack"
            # Finish the partial frame and supply a third frame in the same write.
            carrier.sendall(b"\x03two\x00\x05three")
            for expected in (b"two", b"three"):
                payload, sender = udp.recvfrom(1024)
                assert (payload, sender) == (expected, peer), (payload, sender)

    with socket.socket(type=socket.SOCK_DGRAM) as udp:
        udp.bind(backend)
        udp.settimeout(5)
        startup(binary, {"name": "marked-stream-datagram-boundaries", "nodes": nodes}, exercise=exchange)


def header_direct_connector_cases(binary):
    ingress = ("127.0.0.1", 29845)
    backend_port = 29846
    tcp, udp = make_backends(backend_port)
    with tcp, udp:
        for mode, cases in (
            ("dest_context->protocol", ((b"\x06", tcp), (b"\x11", udp))),
            ("line-mark", ((bytes(16), tcp), (bytes(range(16)), tcp))),
        ):
            nodes = [socket_node("in", "TcpListener", ingress[1], next_node="header"),
                     {"name": "header", "type": "HeaderServer", "settings": {"override": mode}, "next": "out"},
                     socket_node("out", "TcpUdpConnector", backend_port)]

            def exchange(process, deadline):
                for prefix, wanted in cases:
                    with connect_when_ready(process, ingress, deadline=deadline, timeout=5,
                                            failure=lambda: AssertionError("TCP ingress did not start")) as client:
                        client.settimeout(5)
                        client.sendall(prefix + b"Q")
                        ready, _, _ = select.select([tcp, udp], [], [], 5)
                        assert ready == [wanted], (mode, prefix.hex(), ready)
                        if wanted == udp:
                            data, peer = udp.recvfrom(16)
                            assert data == b"Q", data
                            udp.sendto(b"R", peer)
                        else:
                            peer, _ = tcp.accept()
                            with peer:
                                peer.settimeout(5)
                                assert exact(peer, 1) == b"Q"
                                peer.sendall(b"R")
                        assert exact(client, 1) == b"R"

            startup(binary, {"name": "header-direct-" + ("mark" if mode == "line-mark" else "protocol"),
                             "nodes": nodes}, exercise=exchange)


def proxy_cases(binary):
    listener = socket_node("ingress", "TcpListener", 29845, next_node="proxy")
    stream = socket_node("egress", "TcpConnector", 29846)
    datagram = socket_node("egress", "UdpConnector", 29846)
    dual = socket_node("egress", "TcpUdpConnector", 29846)
    proxy = {"name": "proxy", "type": "TrojanServer", "settings": {"password": "fixture",
                                                                 "connect": True, "udp": False},
             "next": "egress"}
    config = {"name": "proxy-connect-only", "nodes": [listener, proxy, stream]}
    startup(binary, config)

    config.update(name="proxy-udp-only", nodes=[listener, proxy, datagram])
    proxy["settings"].update(connect=False, udp=True)
    startup(binary, config)

    config.update(name="proxy-dual", nodes=[listener, proxy, dual])
    proxy["settings"]["connect"] = True
    startup(binary, config)

    config.update(name="proxy-dual-with-stream-only-egress", nodes=[listener, proxy, stream])
    startup(binary, config)


def mixed_encryption_cases(binary):
    from trojanserver_splice_integration import address, frame, receive_frame

    ingress = ("127.0.0.1", 29845)
    backend = ("127.0.0.1", 29846)
    cipher = {"password": "test", "max-frame-size": 16}
    nodes = [
        socket_node("input", "TcpListener", ingress[1], next_node="proxy"),
        {"name": "proxy", "type": "TrojanServer", "next": "encrypt",
         "settings": {"password": "test", "connect": True, "udp": True}},
        {"name": "encrypt", "type": "EncryptionClient", "next": "decrypt", "settings": cipher},
        {"name": "decrypt", "type": "EncryptionServer", "next": "out", "settings": cipher},
        socket_node("out", "TcpUdpConnector", backend[1]),
    ]

    def exchange(process, deadline):
        # Both proxy commands have a TCP ingress. The same Encryption instances must
        # chunk a long CONNECT stream and keep each UDP ASSOCIATE datagram whole.
        password = hashlib.sha224(b"test").hexdigest().encode() + b"\r\n"
        tcp, udp = make_backends(backend[1])
        with tcp, udp:
            with connect_when_ready(process, ingress, deadline=deadline, timeout=5,
                                    failure=lambda: AssertionError("runtime exited before accepting TCP")) as client:
                payload = bytes(range(96))
                client.sendall(password + b"\x01" + address(backend[1]) + b"\r\n" + payload)
                peer, _ = tcp.accept()
                with peer:
                    peer.settimeout(5)
                    assert exact(peer, len(payload)) == payload
                    peer.sendall(payload[::-1])
                    assert exact(client, len(payload)) == payload[::-1]
            with socket.create_connection(ingress, timeout=5) as client:
                client.sendall(password + b"\x03" + address(backend[1]) + b"\r\n" +
                               frame(backend[1], b"") + frame(backend[1], b"x" * 17) +
                               frame(backend[1], b"last"))
                for data in (b"", b"last"):
                    received, peer = udp.recvfrom(512)
                    assert received == data, (received, data)
                    udp.sendto(received, peer)
                    assert receive_frame(client) == (backend[1], data)

    startup(binary, {"name": "mixed-encryption-destination", "nodes": nodes}, exercise=exchange)

    def refused(process, deadline):
        while time.monotonic() < deadline:
            if "UdpConnector: destination does not offer UDP" in process.log_path.read_text(errors="replace"):
                break
            process.check_running("a live transport mismatch stopped the runtime")
            time.sleep(0.01)
        else:
            raise AssertionError("fixed UDP connector did not refuse the locally selected stream")
        assert not select.select([udp], [], [], 0.2)[0], "a TCP selection reached the UDP backend"

    def encrypted_datagram(process, deadline):
        record, _ = udp.recvfrom(65535)
        assert record[:3] == b"\x17\x03\x03", "UDP backend did not receive an encrypted record"
        assert len(record) - 5 == int.from_bytes(record[3:5], "big"), "record crossed datagram boundaries"

    for protocol, exercise in ((None, refused), ("udp", encrypted_datagram)):
        encrypt = {"name": "encrypt", "type": "EncryptionClient", "next": "egress",
                   "settings": {"password": "test", "max-frame-size": 4096}}
        bridge_nodes = [*packet_producer("encrypt", protocol), encrypt,
                        socket_node("egress", "UdpConnector", backend[1])]
        tcp, udp = make_backends(backend[1])
        with tcp, udp:
            startup(binary, {"name": f"encryption-offer-{protocol}", "nodes": bridge_nodes}, exercise=exercise)


def pinned_relay_cases(binary):
    from trojanserver_splice_integration import address

    ingress = ("127.0.0.1", 29845)
    socks_port, relay_port, carrier_port = 29846, 29847, 29848
    listener = socket_node("input", "UdpListener", ingress[1], next_node="socks")
    socks = {"name": "socks", "type": "Socks5Client", "next": "trojan",
             "settings": {"address": "127.0.0.1", "port": socks_port, "protocol": "udp"}}
    trojan = {"name": "trojan", "type": "TrojanClient", "next": "carrier",
              "settings": {"address": "127.0.0.1", "port": socks_port, "protocol": "tcp", "password": "fixture"}}
    receiver = socket_node("carrier-input", "TcpListener", carrier_port, next_node="decode")
    decoder = {"name": "decode", "type": "TrojanServer", "next": "egress",
               "settings": {"password": "fixture", "connect": True, "udp": True}}
    egress = {"name": "egress", "type": "TcpUdpConnector",
              "settings": {"address": "dest_context->address", "port": "dest_context->port"}}
    nodes = [listener, socks, trojan, socket_node("carrier", "TcpConnector", carrier_port), receiver, decoder, egress]

    def exchange(process, deadline):
        listeners = (f"SocketManager: listening on {ingress[0]}:[{ingress[1]}] (UDP)",
                     f"SocketManager: listening on 127.0.0.1:[{carrier_port}] (TCP)")
        while True:
            output = process.log_path.read_text(errors="replace")
            if all(listener in output for listener in listeners):
                break
            process.check_running("runtime exited before binding both listeners")
            if time.monotonic() >= deadline:
                raise AssertionError("runtime did not bind both listeners")
            time.sleep(0.01)

        with socket.socket(type=socket.SOCK_DGRAM) as application:
            application.settimeout(5)
            application.sendto(b"relay marker", ingress)
            control, _ = socks_tcp.accept()
            with control:
                control.settimeout(5)
                assert exact(control, 3) == b"\x05\x01\x00"
                control.sendall(b"\x05\x00")
                request = exact(control, 10)
                assert request[:4] == b"\x05\x03\x00\x01"
                control.sendall(b"\x05\x00\x00" + address(relay_port))
                payload, peer = relay.recvfrom(1024)
                assert payload.startswith(b"\x00\x00\x00\x01") and payload.endswith(b"relay marker")
                relay.sendto(payload, peer)
                assert application.recvfrom(1024)[0] == b"relay marker"

    for protocol in ("udp", "dest_context->protocol"):
        socks["settings"]["protocol"] = protocol
        socks_tcp, unused_udp = make_backends(socks_port)
        with socks_tcp, unused_udp, socket.socket(type=socket.SOCK_DGRAM) as relay:
            relay.bind(("127.0.0.1", relay_port))
            relay.settimeout(5)
            startup(binary, {"name": "pinned-relay-" + protocol[:3], "nodes": nodes}, exercise=exchange)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=lambda value: str(Path(value).resolve()))
    cases = {
        "dispatch": dispatch_cases,
        "header-stream": header_stream_case,
        "header-direct": header_direct_connector_cases,
        "mixed-encryption": mixed_encryption_cases,
        "pinned-relay": pinned_relay_cases,
        "proxy": proxy_cases,
        "quic": quic_cases,
        "routing": routing_cases,
        "routing-context": routing_context_cases,
        "socks-udp-ingress": socks_udp_ingress_cases,
    }
    parser.add_argument("cases", choices=cases)
    args = parser.parse_args()
    install_termination_handler()
    cases[args.cases](args.binary)
