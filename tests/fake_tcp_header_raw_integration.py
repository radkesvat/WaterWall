#!/usr/bin/env python3
"""Isolated raw peers with UDP, native TCP or TUN input and wire checks.

CTest: waterwall.fake_tcp_header_{raw,raw_tcp,tun,raw_multiqueue}_roundtrip.
Run through the network namespace wrapper. --tcp tests native TCP through CTP;
--tun uses deterministic native UDP tuples; --multi-queue requires one effective
RawSocket receive queue per worker on both peers.
"""
import contextlib
import errno
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parent / "support" / "python")))
from wwtest.linux_commands import command, iptables
from wwtest.process import Process, install_termination_handler
from wwtest.run_directory import RunDirectory

WORKERS = 2
FLOWS = 6
NATIVE_MTU = 1476
FAKE_OPTIONS = bytes((1, 1, 1, 1))


def checksum(data):
    data += bytes(len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def flow_index(packet, count):
    """Reference for deviceFlowWorkerHash(packet) % count on one IPv4 packet."""
    ihl = (packet[0] & 15) * 4
    total, fragment = struct.unpack_from("!H2xH", packet, 2)
    protocol = packet[9]
    source, destination = struct.unpack_from("!II", packet, 12)
    source_word = destination_word = fragment_key = 0
    if fragment & 0x3FFF:
        fragment_key = 0x10000 | struct.unpack_from("!H", packet, 4)[0]
    elif protocol in (6, 17, 132) and total >= ihl + 4:
        source_word, destination_word = struct.unpack_from("!HH", packet, ihl)

    def endpoint(address, word):
        value = address ^ ((word * 0x9E3779B1) & 0xFFFFFFFF)
        value ^= value >> 16
        value = (value * 0x85EBCA6B) & 0xFFFFFFFF
        return value ^ (value >> 13)

    value = ((endpoint(source, source_word) + endpoint(destination, destination_word)) & 0xFFFFFFFF)
    value = ((value ^ protocol ^ fragment_key) * 0x9E3779B1) & 0xFFFFFFFF
    return (value ^ (value >> 16)) % count


# The codec unit's known answer: 10.0.0.1:5000 -> 10.0.0.2:53 UDP selects index 1 of 16.
assert flow_index(bytes.fromhex("452e002412344000401114650a0000010a000002138800350010"
                                "756366616b652d746370"), 16) == 1, "flow hash reference diverged from the codec"


def native_packet(source, destination, protocol, transport):
    """Construct a native IPv4 packet independently of the production codec."""
    header = bytearray(struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), 0, 0,
                                   64, protocol, 0, socket.inet_aton(source), socket.inet_aton(destination)))
    struct.pack_into("!H", header, 10, checksum(header))
    return bytes(header) + transport


def deterministic_ports(source, destination, target_port, count):
    """Choose six exact TUN tuples occupying six distinct carrier port indices."""
    selected = {}
    for port in range(20000, 50000):
        transport = struct.pack("!HHHH", port, target_port, 8, 0)
        index = flow_index(native_packet(source, destination, 17, transport), count)
        selected.setdefault(index, port)
        if len(selected) == FLOWS:
            return list(selected.values())
    raise AssertionError("could not select deterministic native flow tuples")


def prepare(directory, role, listener_port, target_port, tun, multi_queue, tcp):
    example_role = "client-tun" if tun and role == "client" else role
    node_directory = "FakeTcpHeaderClient" if role == "client" else "FakeTcpHeaderServer"
    examples = Path(__file__).resolve().parent.parent / "tunnels" / node_directory / "examples" / example_role
    config = json.loads((examples / "config.json").read_text())
    core = json.loads((examples / "core.json").read_text())
    core["misc"].update(workers=WORKERS, mtu=NATIVE_MTU)
    core["log"].update({name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                         for name in ("core", "internal", "network", "dns")})
    carrier_ports = None
    for node in config["nodes"]:
        settings = node.setdefault("settings", {})
        if node["type"] == "RawSocket":
            settings.update({"capture-device-name": "fake-tcp-" + role, "skip-sysctl": True,
                             "multi-queue": multi_queue})
        elif node["type"] in ("FakeTcpHeaderClient", "FakeTcpHeaderServer"):
            settings.update({"payload-protocol": 6 if tcp else 17, "options": FAKE_OPTIONS.hex()})
            carrier_ports = tuple(settings.get(key, default) for key, default in
                                  (("server-port", 40000), ("client-port", 40001), ("client-port-count", 16)))
        elif node["type"] in ("ConnectionToPackets", "PacketsToConnection"):
            settings["mtu"] = NATIVE_MTU
        elif node["type"] == "TunDevice":
            settings.update({"device-ip": "10.253.90.1/24", "device-mtu": NATIVE_MTU, "multi-queue": False})
        elif node["type"] == "IpOverrider" and tun:
            native = ("10.253.90.2", "10.253.90.1") if role == "client" else ("10.253.90.1", "10.253.90.2")
            settings["down" if role == "client" else "up"] = {
                "source-ip": {"ipv4": native[0]}, "dest-ip": {"ipv4": native[1]}}
        elif node["type"] == "UdpListener":
            settings["port"] = listener_port
            if tcp:
                node["type"] = "TcpListener"
                settings["nodelay"] = True
        elif node["type"] == "UdpConnector":
            settings["port"] = target_port
            if tcp:
                node["type"] = "TcpConnector"
                settings.update(nodelay=True, fastopen=False)
    directory.mkdir()
    (directory / "config.json").write_text(json.dumps(config))
    (directory / "core.json").write_text(json.dumps(core))
    return carrier_ports


def receive_exact(sock, length):
    result = bytearray()
    while len(result) < length:
        part = sock.recv(length - len(result))
        assert part, "native TCP stream ended before all payload bytes arrived"
        result.extend(part)
    return bytes(result)


def run(binary, directory, tun, multi_queue, tcp):
    for address in ("192.0.2.10", "198.51.100.10"):
        command("ip", "address", "add", address + "/32", "dev", "lo")
    with contextlib.ExitStack() as stack:
        kind = socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM
        backend = stack.enter_context(socket.socket(socket.AF_INET, kind))
        backend.bind(("127.0.0.1", 0))
        backend.settimeout(5)
        if tcp:
            backend.listen(8)
        reservation = socket.socket(socket.AF_INET, kind)
        reservation.bind(("127.0.0.1", 0))
        listener_port = reservation.getsockname()[1]
        reservation.close()
        processes, carrier_ports = [], set()
        for role in ("server", "client"):
            work = directory / role
            carrier_ports.add(prepare(work, role, listener_port, backend.getsockname()[1], tun, multi_queue, tcp))
            process = stack.enter_context(Process([binary], cwd=work, log_path=work / "stdout.log",
                                                   cleanup_signal=signal.SIGTERM, terminate_timeout=15))
            processes.append(process)
            deadline = time.monotonic() + 15
            # Multi-queue must not fall back to one queue, or it tests nothing new.
            queues = WORKERS if multi_queue else 1
            markers = [f"CaptureDevice: fake-tcp-{role} up with {queues} worker-owned receive queue(s)"]
            # Capture activates before workers bind normal listeners.
            if role == "client" and not tun:
                markers.append(f"SocketManager: listening on 127.0.0.1:[{listener_port}] ({'TCP' if tcp else 'UDP'})")
            while not all(marker in (work / "stdout.log").read_text() for marker in markers):
                process.check_running(role + " exited before capture activation")
                assert time.monotonic() < deadline, role + " input did not activate"
                time.sleep(0.05)
        assert len(carrier_ports) == 1, "example peers disagree on carrier ports"
        server_port, client_port, client_port_count = carrier_ports.pop()

        if tun:
            deadline = time.monotonic() + 10
            while True:
                processes[-1].check_running("client exited before TUN activation")
                result = subprocess.run(["ip", "-j", "address", "show", "dev", "wwfake0"],
                                        capture_output=True, text=True, timeout=10)
                interfaces = json.loads(result.stdout) if result.returncode == 0 else []
                if any("UP" in item["flags"] and item["mtu"] == NATIVE_MTU and
                       any(address.get("local") == "10.253.90.1" for address in item.get("addr_info", []))
                       for item in interfaces):
                    break
                assert time.monotonic() < deadline, "TUN did not activate"
                time.sleep(0.05)

        # Genuine TCP from either captured peer IP must stay in the host stack.
        # It differs from the reserved fake carrier tuple only in its TCP ports.
        for local, peer in (("192.0.2.10", "198.51.100.10"), ("198.51.100.10", "192.0.2.10")):
            with socket.socket() as listener, socket.socket() as ordinary:
                listener.bind((peer, 0))
                listener.listen(1)
                listener.settimeout(5)
                ordinary.settimeout(5)
                ordinary.bind((local, 0))
                ordinary.connect(listener.getsockname())
                accepted, _ = listener.accept()
                with accepted:
                    accepted.settimeout(5)
                    ordinary.sendall(b"ordinary-tcp-request")
                    assert accepted.recv(128) == b"ordinary-tcp-request", "filter stole genuine TCP"
                    accepted.sendall(b"ordinary-tcp-reply")
                    assert ordinary.recv(128) == b"ordinary-tcp-reply", "filter stole genuine TCP reply"

        # Protocol 17 must reach ordinary host UDP sockets on each receive side.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_backend:
            udp_backend.bind(("127.0.0.1", 0))
            udp_backend.settimeout(5)
            for address in ("192.0.2.10", "198.51.100.10"):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ordinary:
                    ordinary.bind((address, 0))
                    ordinary.sendto(b"unrelated-udp", udp_backend.getsockname())
                    assert udp_backend.recv(65535) == b"unrelated-udp", "allowlist captured ordinary UDP"

        wire = stack.enter_context(socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800)))
        wire.bind(("lo", 0))
        wire.settimeout(0.2)
        native_ips = ("10.253.90.1", "10.253.90.2") if tun else ("10.90.0.1", "10.90.0.2")
        native_target = listener_port if tun else 5300
        chosen_ports = deterministic_ports(*native_ips, native_target, client_port_count) if tun else [0] * FLOWS
        requests, responses = set(), set()
        seen = {"192.0.2.10": set(), "198.51.100.10": set()}
        observed_mapping, user_ports, association_ports, expected_streams = {}, {}, {}, {}
        tcp_segments, tcp_origins = {}, {}
        tcp_flags = {"192.0.2.10": set(), "198.51.100.10": set()}
        observed_client_ports = set()
        current_user = 0

        def inspect(frame):
            packet = frame[14:]
            if len(packet) < 44 or packet[9] != 6:
                return
            source = socket.inet_ntoa(packet[12:16])
            if source not in seen:
                return
            total = struct.unpack_from("!H", packet, 2)[0]
            assert total <= len(packet), "truncated carrier frame"
            packet = packet[:total]
            ihl = (packet[0] & 15) * 4
            assert ihl == 20, "unexpected generated native IPv4 options"
            carrier = packet[ihl:]
            ports = struct.unpack_from("!HH", carrier)
            # Every carrier has the server port on one side; anything else is genuine TCP.
            if server_port not in ports:
                return
            forward = source == "192.0.2.10"
            client_side, server_side = ports if forward else ports[::-1]
            assert server_side == server_port, "carrier server port is on the wrong side"
            assert client_port <= client_side < client_port + client_port_count, \
                "carrier client port outside the configured range"
            assert socket.inet_ntoa(packet[16:20]) == ("198.51.100.10" if forward else "192.0.2.10")
            assert total <= 1500, "carrier exceeded configured MTU"
            assert checksum(packet[:ihl]) == 0, "invalid IPv4 wire checksum"
            pseudo = packet[12:20] + struct.pack("!BBH", 0, 6, len(carrier))
            assert checksum(pseudo + carrier) == 0, "invalid fake TCP wire checksum"
            fake_length = (carrier[12] >> 4) * 4
            assert fake_length == 24
            native = carrier[fake_length:]
            assert len(native) >= (20 if tcp else 8), "missing native transport header"
            native_ports = struct.unpack_from("!HH", native)
            native_client, native_server = native_ports if forward else native_ports[::-1]
            assert native_server == native_target, "native header is not immediately after fake TCP"
            # CTP chooses its own ephemeral native port; TUN tuples are chosen in advance.
            if native_client not in user_ports:
                assert forward, "reply arrived without its native request tuple"
                user_ports[native_client] = current_user
            user = user_ports[native_client]
            assert association_ports.setdefault(user, native_client) == native_client, \
                "one application association changed its native source port"
            if tun:
                assert native_client == chosen_ports[user], "TUN source tuple changed"
            addresses = native_ips if forward else native_ips[::-1]
            protocol = 6 if tcp else 17
            native_pseudo = bytes(8) + struct.pack("!BBH", 0, protocol, len(native))
            assert (not tcp and native[6:8] == bytes(2)) or checksum(native_pseudo + native) == 0, \
                "hidden native checksum does not use zero address contributions"

            # Restore the checksum independently and hash the encoder's native
            # tuple, never the rewritten carrier or a nested IPv4 interpretation.
            restored = bytearray(native)
            checksum_offset = 16 if tcp else 6
            if tcp or native[6:8] != bytes(2):
                restored[checksum_offset:checksum_offset + 2] = bytes(2)
                value = checksum(socket.inet_aton(addresses[0]) + socket.inet_aton(addresses[1]) +
                                 struct.pack("!BBH", 0, protocol, len(restored)) + restored)
                struct.pack_into("!H", restored, checksum_offset, value or (0 if tcp else 65535))
            reconstructed = native_packet(*addresses, protocol, restored)
            expected_port = client_port + flow_index(reconstructed, client_port_count)
            assert client_side == expected_port, "carrier port does not follow the native flow mapping"
            key = (source, native_client)
            assert observed_mapping.setdefault(key, client_side) == client_side, "carrier flow mapping changed"
            observed_client_ports.add(client_side)

            # Independently serialize the configured fake header. Comparing its
            # exact placement and total length excludes an extra IPv4 header.
            sequence, acknowledgment = (12345, 67890) if forward else (67890, 12345)
            expected_fake = bytearray(struct.pack("!HHIIBBHHH", *ports, sequence, acknowledgment,
                                                 0x60, 0x18, 65535, 0, 0) + FAKE_OPTIONS)
            struct.pack_into("!H", expected_fake, 16, checksum(pseudo + expected_fake + native))
            assert carrier[:fake_length] == expected_fake, "configured fake TCP header did not reach wire"
            assert total == 20 + 24 + len(native) and total - 24 <= NATIVE_MTU
            if tcp:
                native_length = (native[12] >> 4) * 4
                assert 20 <= native_length <= len(native), "invalid native TCP data offset"
                flags = native[13]
                tcp_flags[source].add(flags)
                sequence = struct.unpack_from("!I", native, 4)[0]
                if flags & 0x02:
                    origin = (sequence + 1) & 0xFFFFFFFF
                    assert tcp_origins.setdefault((source, user), origin) == origin, "native SYN sequence changed"
                payload = native[native_length:]
                if payload:
                    assert (source, user) in tcp_origins, "native data arrived without its handshake"
                    offset = (sequence - tcp_origins[(source, user)]) & 0xFFFFFFFF
                    segments = tcp_segments.setdefault((source, user), {})
                    assert segments.setdefault(offset, payload) == payload, "native retransmission changed bytes"
            else:
                assert struct.unpack_from("!H", native, 4)[0] == len(native)
                payload = native[8:]
                expected_udp = bytearray(struct.pack("!HHHH", *native_ports, 8 + len(payload), 0) + payload)
                if native[6:8] != bytes(2):
                    struct.pack_into("!H", expected_udp, 6, checksum(native_pseudo + expected_udp) or 65535)
                assert native == expected_udp and total == 20 + 24 + 8 + len(payload), \
                    "wire is not exactly IPv4/fake-TCP/native-UDP/application"
                seen[source].add(payload)

        def drain():
            while True:
                try:
                    inspect(wire.recv(65535))
                except TimeoutError:
                    return

        def tcp_complete():
            for user, expected in expected_streams.items():
                for source, payload in zip(seen, expected):
                    segments = tcp_segments.get((source, user), {})
                    if b"".join(segments[offset] for offset in sorted(segments)) != payload:
                        return False
            return True

        # TUN uses six chosen tuples with six distinct expected buckets. CTP's
        # internal ephemeral ports are checked exactly without a random spread assertion.
        for user in range(1 if tcp else FLOWS):
            current_user = user
            application = stack.enter_context(socket.socket(socket.AF_INET, kind))
            application.bind((native_ips[0] if tun else "127.0.0.1", chosen_ports[user]))
            application.settimeout(5)
            destination = (native_ips[1], listener_port) if tun else ("127.0.0.1", listener_port)
            if tcp:
                application.connect(destination)
                accepted, _ = backend.accept()
                accepted = stack.enter_context(accepted)
                accepted.settimeout(5)
                assert application.getpeername() == destination, "TCP reply tuple changed"
            if tun:
                application.setsockopt(socket.IPPROTO_IP, 10, 2)  # IP_MTU_DISCOVER, IP_PMTUDISC_DO
                try:
                    application.sendto(bytes(1449), destination)
                except OSError as error:
                    assert error.errno == errno.EMSGSIZE, "wrong oversized TUN datagram refusal"
                else:
                    raise AssertionError("TUN MTU admitted an oversized UDP datagram")
            sent, received = bytearray(), bytearray()
            for length in (1, 513, 1400) if tcp else (1, 513, 1448):
                payload = bytes((i * 37 + user) & 255 for i in range(length))
                reply = bytes(value ^ 0xa5 for value in payload)
                if tcp:
                    application.sendall(payload)
                    assert receive_exact(accepted, length) == payload, "server changed native TCP request bytes"
                    accepted.sendall(reply)
                    assert receive_exact(application, length) == reply, "client changed native TCP reply bytes"
                    sent.extend(payload)
                    received.extend(reply)
                else:
                    application.sendto(payload, destination)
                    actual, peer = backend.recvfrom(65535)
                    assert actual == payload, "server did not deliver exact UDP payload"
                    backend.sendto(reply, peer)
                    actual, reply_peer = application.recvfrom(65535)
                    assert actual == reply, "client did not restore exact UDP reply"
                    assert reply_peer == destination, "client changed the original UDP source tuple"
                    requests.add(payload)
                    responses.add(reply)
            if tcp:
                expected_streams[user] = (bytes(sent), bytes(received))
            drain()

        deadline = time.monotonic() + 5
        while not (tcp_complete() if tcp else
                   seen["192.0.2.10"] == requests and seen["198.51.100.10"] == responses):
            assert time.monotonic() < deadline, "missing native transport wire packets"
            try:
                inspect(wire.recv(65535))
            except TimeoutError:
                continue
        assert observed_client_ports, "no fake TCP carrier was inspected"
        for native_client in user_ports:
            assert observed_mapping[("192.0.2.10", native_client)] == observed_mapping[("198.51.100.10", native_client)], \
                "reverse native tuple selected a different carrier port"
        if tun:
            expected_ports = {client_port + flow_index(native_packet(*native_ips, 17,
                              struct.pack("!HHHH", port, native_target, 8, 0)), client_port_count)
                              for port in chosen_ports}
            assert len(expected_ports) == FLOWS and observed_client_ports == expected_ports, \
                "deterministic native tuples did not reach every expected carrier bucket"
        if tcp:
            assert 0x02 in tcp_flags["192.0.2.10"], "native SYN was not carried"
            assert 0x12 in tcp_flags["198.51.100.10"], "native SYN/ACK was not carried"
            assert any(flags & 0x10 and not flags & 0x02 for flags in tcp_flags["192.0.2.10"]), \
                "native handshake ACK was not carried"

        for process in reversed(processes):
            process.terminate()
            assert process.wait(timeout=15) in (0, 143), "peer failed orderly shutdown"
        assert "WWCAP" not in iptables("-S", "INPUT"), "capture rules survived shutdown"
        assert "WWCAP_NOTRACK" not in iptables("-t", "raw", "-S", "PREROUTING")
        assert "WWRAW_NOTRACK" not in iptables("-t", "raw", "-S", "OUTPUT")


def main():
    binary = str(Path(sys.argv[1]).resolve())
    options = sys.argv[2:]
    assert set(options) <= {"--tun", "--multi-queue", "--tcp"}, f"unknown options {options}"
    assert not ("--tun" in options and "--tcp" in options), "TCP mode uses the CTP input fixture"
    with RunDirectory(prefix="waterwall-fake-tcp-") as temporary:
        directory = Path(temporary)
        try:
            run(binary, directory, "--tun" in options, "--multi-queue" in options, "--tcp" in options)
        except Exception:
            for log in directory.rglob("stdout.log"):
                print(f"{log}:\n{log.read_text()[-12000:]}", file=sys.stderr)
            raise
    print("Single-IP fake TCP layout/checksums, native flow ports, exact UDP/TCP/TUN request/reply, MTU, "
          "capture exclusions and cleanup passed")


if __name__ == "__main__":
    install_termination_handler()
    main()
