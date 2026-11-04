#!/usr/bin/env python3
"""One direct TUN/raw pair carries TCP, UDP, ICMP and opaque IPv4 packets.

CTest: waterwall.fake_tcp_header_mixed_packet_roundtrip. Run only through the
network namespace wrapper; the two unassigned native peers must route into TUN.
"""
import contextlib
import json
import os
from pathlib import Path
import signal
import socket
import struct
import sys
import time

sys.dont_write_bytecode = True
from fake_tcp_header_raw_integration import (FAKE_OPTIONS, NATIVE_MTU, checksum,
                                             flow_index, native_packet, receive_exact)
from wwtest.linux_commands import command, iptables
from wwtest.process import Process, install_termination_handler
from wwtest.run_directory import RunDirectory

CARRIER = ("192.0.2.10", "198.51.100.10")
CLIENT = ("10.253.90.1", "10.253.90.2")
SERVER = ("10.253.91.1", "10.253.91.2")
TUN_NAMES = ("wwmixc0", "wwmixs0")
SERVER_PORT, CLIENT_PORT, PORT_COUNT = 40000, 40001, 16
PROTOCOLS = (6, 17, 1, 253)


def addresses(source, destination):
    return {"source-ip": {"ipv4": source}, "dest-ip": {"ipv4": destination}}


def prepare(directory, role):
    client = role == "client"
    native = CLIENT if client else SERVER
    tun = {"name": "native", "type": "TunDevice", "settings": {
        "device-name": TUN_NAMES[0 if client else 1], "device-ip": native[0] + "/24",
        "device-mtu": NATIVE_MTU, "gso": False, "multi-queue": False, "route-table": "off"}}
    fake = {"name": "fake", "type": "FakeTcpHeaderClient" if client else "FakeTcpHeaderServer",
            "settings": {"server-port": SERVER_PORT, "client-port": CLIENT_PORT,
                         "client-port-count": PORT_COUNT, "options": FAKE_OPTIONS.hex(),
                         "sequence": 12345 if client else 67890,
                         "acknowledgment": 67890 if client else 12345}}
    rewrite = {"name": "addresses", "type": "IpOverrider", "settings": {
        "up" if client else "down": addresses(*(CARRIER if client else CARRIER[::-1])),
        "down" if client else "up": addresses(native[1], native[0])}}
    raw = {"name": "raw", "type": "RawSocket", "settings": {
        "capture-device-name": "fake-tcp-mixed-" + role, "skip-sysctl": True,
        "multi-queue": False, "capture-filter-mode": "source-ip",
        "capture-ips": [CARRIER[1 if client else 0]], "capture-protocols": [6],
        "capture-tcp-source-port" if client else "capture-tcp-dest-port": SERVER_PORT}}
    nodes = [tun, fake, rewrite, raw] if client else [raw, rewrite, fake, tun]
    for node, following in zip(nodes, nodes[1:]):
        node["next"] = following["name"]
    core = {"configs": ["config.json"],
            "misc": {"workers": 2, "ram-profile": "client", "mtu": NATIVE_MTU,
                     "try-enabling-bbr": False},
            "log": {"path": "log/", **{
                name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                for name in ("core", "internal", "network", "dns")}}}
    directory.mkdir()
    (directory / "config.json").write_text(json.dumps({"name": "mixed-" + role, "nodes": nodes}))
    (directory / "core.json").write_text(json.dumps(core))


def wait_ready(process, work, role):
    client = role == "client"
    name = TUN_NAMES[0 if client else 1]
    native = CLIENT if client else SERVER
    deadline = time.monotonic() + 15
    marker = f"CaptureDevice: fake-tcp-mixed-{role} up with 1 worker-owned receive queue(s)"
    while True:
        process.check_running(role + " exited before packet inputs activated")
        interfaces = json.loads(command("ip", "-j", "address", "show"))
        tun_up = any(item["ifname"] == name and "UP" in item["flags"] and item["mtu"] == NATIVE_MTU
                     and any(address.get("local") == native[0] for address in item.get("addr_info", []))
                     for item in interfaces)
        if tun_up and marker in (work / "stdout.log").read_text():
            return
        assert time.monotonic() < deadline, role + " packet inputs did not activate"
        time.sleep(0.05)


def receive_raw(sock, protocol, source, destination):
    packet, peer = sock.recvfrom(65535)
    ihl = (packet[0] & 15) * 4
    assert packet[0] >> 4 == 4 and 20 <= ihl <= len(packet), "malformed received native IPv4"
    assert peer[0] == source and socket.inet_ntoa(packet[12:16]) == source, "native source address changed"
    assert socket.inet_ntoa(packet[16:20]) == destination and packet[9] == protocol, "native tuple changed"
    assert struct.unpack_from("!H", packet, 2)[0] == len(packet) and checksum(packet[:ihl]) == 0
    return packet[ihl:]


def run(binary, directory):
    parent_netns = os.environ.get("WATERWALL_TEST_PARENT_NETNS")
    assert parent_netns and os.readlink("/proc/self/ns/net") != parent_netns, \
        "mixed packet test requires the private network namespace wrapper"
    with contextlib.ExitStack() as stack:
        for address in CARRIER:
            command("ip", "address", "add", address + "/32", "dev", "lo")
            stack.callback(command, "ip", "address", "del", address + "/32", "dev", "lo")
        processes = []
        for role in ("server", "client"):
            work = directory / role
            prepare(work, role)
            process = stack.enter_context(Process([binary], cwd=work, log_path=work / "stdout.log",
                                                   cleanup_signal=signal.SIGTERM, terminate_timeout=15))
            processes.append(process)
            wait_ready(process, work, role)
        # Assigning these peers locally would bypass the encoder entirely.
        assigned = {address.get("local") for item in json.loads(command("ip", "-j", "address", "show"))
                    for address in item.get("addr_info", [])}
        assert CLIENT[1] not in assigned and SERVER[1] not in assigned, "native peer alias bypasses TUN"

        def opened(kind, protocol=0, bind=None):
            sock = stack.enter_context(socket.socket(socket.AF_INET, kind, protocol))
            sock.settimeout(5)
            if bind is not None:
                sock.bind(bind)
            return sock

        tcp_server = opened(socket.SOCK_STREAM, bind=(SERVER[0], 0))
        tcp_server.listen(1)
        udp_server = opened(socket.SOCK_DGRAM, bind=(SERVER[0], 0))
        udp_client = opened(socket.SOCK_DGRAM, bind=(CLIENT[0], 0))
        icmp_server = opened(socket.SOCK_RAW, socket.IPPROTO_ICMP, (SERVER[0], 0))
        icmp_client = opened(socket.SOCK_RAW, socket.IPPROTO_ICMP, (CLIENT[0], 0))
        opaque_server = opened(socket.SOCK_RAW, 253, (SERVER[0], 0))
        opaque_client = opened(socket.SOCK_RAW, 253, (CLIENT[0], 0))
        wire = stack.enter_context(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)))
        wire.bind(("lo", 0))
        wire.settimeout(0.1)
        wire.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
        seen = {(source, protocol): set() for source in CARRIER for protocol in PROTOCOLS}
        tcp_flags = {source: set() for source in CARRIER}
        tcp_origins, tcp_segments = {}, {}
        expected = {protocol: (set(), set()) for protocol in (17, 1, 253)}
        streams = (bytearray(), bytearray())

        def inspect(frame):
            packet = frame[14:]
            if len(packet) < 40 or packet[0] >> 4 != 4 or packet[9] != 6:
                return
            source = socket.inet_ntoa(packet[12:16])
            if source not in CARRIER:
                return
            forward = source == CARRIER[0]
            ihl = (packet[0] & 15) * 4
            total = struct.unpack_from("!H", packet, 2)[0]
            assert ihl == 20 and ihl + 20 <= total <= min(len(packet), 1500), "invalid carrier geometry"
            packet = packet[:total]
            assert socket.inet_ntoa(packet[16:20]) == CARRIER[1 if forward else 0]
            carrier = packet[ihl:]
            ports = struct.unpack_from("!HH", carrier)
            client_port, server_port = ports if forward else ports[::-1]
            if server_port != SERVER_PORT:
                return
            assert CLIENT_PORT <= client_port < CLIENT_PORT + PORT_COUNT, "carrier client port escaped range"
            assert not struct.unpack_from("!H", packet, 6)[0] & 0x3FFF, "fragmented carrier"
            assert checksum(packet[:ihl]) == 0, "bad carrier IPv4 checksum"
            pseudo = packet[12:20] + struct.pack("!BBH", 0, 6, len(carrier))
            assert checksum(pseudo + carrier) == 0, "bad visible TCP checksum, including the protocol byte"
            fake_length = (carrier[12] >> 4) * 4
            assert fake_length == 24 and carrier[20:fake_length] == FAKE_OPTIONS
            assert len(carrier) > fake_length, "carrier lacks a protocol byte"
            protocol = carrier[fake_length]
            assert protocol in PROTOCOLS, f"unexpected received protocol byte {protocol}"
            native = carrier[fake_length + 1:]
            assert total == ihl + fake_length + 1 + len(native) and total - fake_length - 1 <= NATIVE_MTU
            native_addresses = CLIENT if forward else SERVER
            reconstructed = native_packet(*native_addresses, protocol, native)
            assert client_port == CLIENT_PORT + flow_index(reconstructed, PORT_COUNT), \
                "carrier port does not match this encoder's native tuple"
            if protocol in (6, 17):
                assert len(native) >= (20 if protocol == 6 else 8), "truncated native transport header"
                length = len(native) if protocol == 6 else struct.unpack_from("!H", native, 4)[0]
                assert 8 <= length <= len(native)
                normalized_pseudo = bytes(8) + struct.pack("!BBH", 0, protocol, length)
                assert (protocol == 17 and native[6:8] == bytes(2)) or \
                    checksum(normalized_pseudo + native[:length]) == 0, "native checksum was not normalized"
                if protocol == 17:
                    assert length == len(native)
                    seen[(source, protocol)].add(native[8:])
                else:
                    header_length = (native[12] >> 4) * 4
                    assert 20 <= header_length <= len(native)
                    flags = native[13]
                    tcp_flags[source].add(flags)
                    sequence = struct.unpack_from("!I", native, 4)[0]
                    if flags & 2:
                        origin = (sequence + 1) & 0xFFFFFFFF
                        assert tcp_origins.setdefault(source, origin) == origin, "native TCP SYN changed"
                    payload = native[header_length:]
                    if payload:
                        assert source in tcp_origins, "native TCP data preceded its handshake"
                        offset = (sequence - tcp_origins[source]) & 0xFFFFFFFF
                        segments = tcp_segments.setdefault(source, {})
                        assert segments.setdefault(offset, payload) == payload, "native retransmission changed payload"
                    seen[(source, protocol)].add(native)
            elif protocol == 1:
                assert len(native) >= 8 and checksum(native) == 0, "bad native ICMP checksum"
                assert native[:2] == bytes((8 if forward else 0, 0)), "unexpected ICMP echo type/code"
                seen[(source, protocol)].add(native[8:])
            else:
                # Protocol 253 has no checksum convention in this fixture.
                seen[(source, protocol)].add(native)

        def drain():
            deadline = time.monotonic() + 0.3
            while time.monotonic() < deadline:
                try:
                    inspect(wire.recv(65535))
                except TimeoutError:
                    return

        tcp_client = opened(socket.SOCK_STREAM, bind=(CLIENT[0], 0))
        tcp_destination = (CLIENT[1], tcp_server.getsockname()[1])
        tcp_client.connect(tcp_destination)
        accepted, peer = tcp_server.accept()
        accepted = stack.enter_context(accepted)
        accepted.settimeout(5)
        assert peer == (SERVER[1], tcp_client.getsockname()[1]), "server received the wrong TCP peer"
        assert tcp_client.getpeername() == tcp_destination, "client received the wrong TCP peer"
        drain()
        # Keep this exact pair running while packet protocols alternate twice.
        for sequence in range(2):
            payload = bytes((value * 37 + sequence) & 255 for value in range(73 + sequence * 2))
            reply = bytes(value ^ 0xA5 for value in payload)
            udp_destination = (CLIENT[1], udp_server.getsockname()[1])
            udp_client.sendto(payload, udp_destination)
            actual, peer = udp_server.recvfrom(65535)
            assert actual == payload and peer == (SERVER[1], udp_client.getsockname()[1]), "server UDP bytes/tuple changed"
            udp_server.sendto(reply, peer)
            actual, peer = udp_client.recvfrom(65535)
            assert actual == reply and peer == udp_destination, "client UDP bytes/tuple changed"
            expected[17][0].add(payload)
            expected[17][1].add(reply)

            echo = bytearray(struct.pack("!BBHHH", 8, 0, 0, 0x4F57, sequence) + payload)
            struct.pack_into("!H", echo, 2, checksum(echo))
            icmp_client.sendto(echo, (CLIENT[1], 0))
            assert receive_raw(icmp_server, 1, SERVER[1], SERVER[0]) == echo, "server ICMP bytes changed"
            echo_reply = bytearray(echo)
            echo_reply[0] = 0
            echo_reply[2:4] = bytes(2)
            struct.pack_into("!H", echo_reply, 2, checksum(echo_reply))
            assert receive_raw(icmp_client, 1, CLIENT[1], CLIENT[0]) == echo_reply, "client ICMP reply changed"
            expected[1][0].add(payload)
            expected[1][1].add(payload)

            opaque = b"\x00\xff\x45\x00opaque-request-" + payload
            opaque_reply = b"\xff\x00opaque-reply-" + reply
            opaque_client.sendto(opaque, (CLIENT[1], 0))
            assert receive_raw(opaque_server, 253, SERVER[1], SERVER[0]) == opaque, "server opaque bytes changed"
            opaque_server.sendto(opaque_reply, (SERVER[1], 0))
            assert receive_raw(opaque_client, 253, CLIENT[1], CLIENT[0]) == opaque_reply, "client opaque bytes changed"
            expected[253][0].add(opaque)
            expected[253][1].add(opaque_reply)

            tcp_client.sendall(payload)
            assert receive_exact(accepted, len(payload)) == payload, "server TCP bytes changed"
            accepted.sendall(reply)
            assert receive_exact(tcp_client, len(reply)) == reply, "client TCP bytes changed"
            streams[0].extend(payload)
            streams[1].extend(reply)
            drain()

        def complete():
            for index, source in enumerate(CARRIER):
                if not all(seen[(source, protocol)] == expected[protocol][index] for protocol in (17, 1, 253)):
                    return False
                segments = tcp_segments.get(source, {})
                if b"".join(segments[offset] for offset in sorted(segments)) != streams[index]:
                    return False
            return True

        deadline = time.monotonic() + 5
        while not complete():
            assert time.monotonic() < deadline, "missing mixed-protocol carrier bytes"
            drain()
        assert 2 in tcp_flags[CARRIER[0]] and 0x12 in tcp_flags[CARRIER[1]], "native TCP handshake was not carried"
        assert any(flags & 0x10 and not flags & 2 for flags in tcp_flags[CARRIER[0]]), "native handshake ACK was not carried"
        assert all(seen[key] for key in seen), "not every protocol byte reached both carrier directions"

        for process in reversed(processes):
            process.terminate()
            assert process.wait(timeout=15) in (0, 143), "mixed peer failed orderly shutdown"
        assert not set(TUN_NAMES) & {item["ifname"] for item in json.loads(command("ip", "-j", "link", "show"))}, \
            "TUN interface survived peer shutdown"
        assert "WWCAP" not in iptables("-S", "INPUT"), "capture rules survived shutdown"
        assert "WWCAP_NOTRACK" not in iptables("-t", "raw", "-S", "PREROUTING")
        assert "WWRAW_NOTRACK" not in iptables("-t", "raw", "-S", "OUTPUT")


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with RunDirectory(prefix="waterwall-fake-tcp-mixed-") as directory:
        try:
            run(binary, Path(directory))
        except Exception:
            for log in Path(directory).rglob("stdout.log"):
                print(f"{log}:\n{log.read_text()[-12000:]}", file=sys.stderr)
            raise
    print("One direct TUN/raw pair carried exact TCP/UDP/ICMP/opaque bytes and tuples in both directions; "
          "wire tags, checksums, native flow ports and cleanup passed")


if __name__ == "__main__":
    install_termination_handler()
    main()
