#!/usr/bin/env python3
"""Isolated raw peers with UDP, native TCP or TUN input and wire checks.

CTest: waterwall.fake_tcp_header_{raw,raw_tcp,tun,raw_multiqueue}_roundtrip.
Run through the network namespace wrapper. --tcp tests native TCP through CTP;
--tun uses deterministic native UDP tuples; --multi-queue requires one effective
RawSocket receive queue per worker on both peers. UDP uses the random-port
sequence default, --multi-queue uses random-node starts, --tcp uses numeric
starts, and --tun explicitly disables increments with numeric starts. Advancing
byte ranges are checked per direction/client port without assuming arrival order.
ACK modes are random-packet for UDP, random-node for --multi-queue, numeric for
--tcp, and random-port for --tun. TCP/TUN ACKs advance once per encoded packet;
multiqueue ACKs remain fixed within each node. TCP/TUN also use short flag scripts
including SYN/FIN/RST and non-ACK carriers, with the last entry repeated.
--encrypted exercises the optional password helper with UDP, checks its 40-byte
expansion in packet lengths and sequences, and rejects a tampered carrier.
"""
from collections import Counter
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
NATIVE_MTU = 1475
FAKE_OPTIONS = bytes((1, 1, 1, 1))
TCP_ACK_STARTS = (0xFFFFFFFE, 0xFFFFFFFD)
ENCRYPTION_OVERHEAD = 40
ENCRYPTION_PASSWORD = "fake-tcp-packet-integration-shared-secret"


def checksum(data):
    data = bytes(data) + bytes(len(data) % 2)
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


def check_sequence_ranges(ranges, key, expected_initial=None, field="sequence"):
    """Check captured counter ranges, allowing reordering and uint32 wrap."""
    assert len(ranges) > 1, f"fake {field} did not advance for {key}"
    # The finite workload occupies fewer than 2^31 counter units. Relative signed
    # offsets put earlier packets before the first observed packet, even when
    # a random starting value wraps during the capture.
    anchor = next(iter(ranges))
    ordered = sorted((((sequence - anchor + (1 << 31)) & 0xFFFFFFFF) - (1 << 31), entry)
                     for sequence, entry in ranges.items())
    first_offset = expected_offset = ordered[0][0]
    initial = (anchor + first_offset) & 0xFFFFFFFF
    if expected_initial is not None:
        assert initial == expected_initial, f"fake {field} did not start at its configured value for {key}"
    for offset, (length, _) in ordered:
        assert offset == expected_offset, f"fake {field} ranges overlap or leave a gap for {key}"
        expected_offset += length  # Sequence: fake payload plus SYN/FIN; acknowledgment: one packet.
    assert expected_offset - first_offset < 1 << 31, f"fake {field} escaped the bounded probe workload"
    return initial


def prepare(directory, role, listener_port, target_port, tun, multi_queue, tcp, encrypted=False):
    native_mtu = NATIVE_MTU - (ENCRYPTION_OVERHEAD if encrypted else 0)
    example_role = "client-tun" if tun and role == "client" else role
    node_directory = "FakeTcpHeaderClient" if role == "client" else "FakeTcpHeaderServer"
    examples = Path(__file__).resolve().parent.parent / "tunnels" / node_directory / "examples" / example_role
    config = json.loads((examples / "config.json").read_text())
    core = json.loads((examples / "core.json").read_text())
    core["misc"].update(workers=WORKERS, mtu=native_mtu)
    core["log"].update({name: {"loglevel": "DEBUG", "file": name + ".log", "console": True}
                         for name in ("core", "internal", "network", "dns")})
    carrier_ports = None
    for node in config["nodes"]:
        settings = node.setdefault("settings", {})
        if node["type"] == "RawSocket":
            settings.update({"capture-device-name": "fake-tcp-" + role, "skip-sysctl": True,
                             "multi-queue": multi_queue})
        elif node["type"] in ("FakeTcpHeaderClient", "FakeTcpHeaderServer"):
            settings["options"] = FAKE_OPTIONS.hex()
            if encrypted:
                settings["password"] = ENCRYPTION_PASSWORD
            if tcp:
                settings["flags"] = [{"syn": True}, {"fin": True, "rst": True}, {"ack": True, "psh": True}]
            elif tun:
                settings["flags"] = [{"syn": True, "fin": True, "rst": True}, {}]
            else:
                settings.pop("flags", None)
            if tun:
                settings["acknowledgment"] = "random_port"
            elif tcp:
                settings["acknowledgment"] = TCP_ACK_STARTS[0 if role == "client" else 1]
            elif multi_queue:
                settings["acknowledgment"] = "random_node"
            else:
                settings["acknowledgment"] = "random_packet"
            if tun or tcp:
                settings["increment-acknowledgment"] = True
            else:
                settings.pop("increment-acknowledgment", None)
            if tun or tcp:
                settings["sequence"] = 12345 if role == "client" else 67890
            elif multi_queue:
                settings["sequence"] = "random_node"
            else:
                settings.pop("sequence", None)
            if tun:
                settings["increment-sequence"] = False
            else:
                settings.pop("increment-sequence", None)
            if "client-port" in settings:
                first = last = settings["client-port"]
            else:
                first, last = settings.get("client-port-range", [40001, 40016])
            carrier_ports = settings.get("server-port", 40000), first, last - first + 1
        elif node["type"] in ("ConnectionToPackets", "PacketsToConnection"):
            settings["mtu"] = native_mtu
        elif node["type"] == "TunDevice":
            settings.update({"device-ip": "10.253.90.1/24", "device-mtu": native_mtu, "multi-queue": False})
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


def run(binary, directory, tun, multi_queue, tcp, encrypted=False):
    native_mtu = NATIVE_MTU - (ENCRYPTION_OVERHEAD if encrypted else 0)
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
            carrier_ports.add(prepare(work, role, listener_port, backend.getsockname()[1], tun, multi_queue, tcp, encrypted))
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
                if any("UP" in item["flags"] and item["mtu"] == native_mtu and
                       any(address.get("local") == "10.253.90.1" for address in item.get("addr_info", []))
                       for item in interfaces):
                    break
                assert time.monotonic() < deadline, "TUN did not activate"
                time.sleep(0.05)

        # TCP from unselected source IPs must stay in the host stack. Selected
        # peer IPs deliberately capture all TCP ports, including ordinary TCP.
        for local, peer in (("127.0.0.1", "127.0.0.2"), ("127.0.0.2", "127.0.0.1")):
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
                    assert receive_exact(accepted, 20) == b"ordinary-tcp-request", "filter captured unselected TCP"
                    accepted.sendall(b"ordinary-tcp-reply")
                    assert receive_exact(ordinary, 18) == b"ordinary-tcp-reply", "filter captured unselected TCP reply"

        # Protocol 17 must reach ordinary host UDP sockets on each receive side.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_backend:
            udp_backend.bind(("127.0.0.1", 0))
            udp_backend.settimeout(5)
            for address in ("192.0.2.10", "198.51.100.10"):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as ordinary:
                    ordinary.bind((address, 0))
                    ordinary.sendto(b"unrelated-udp", udp_backend.getsockname())
                    assert udp_backend.recv(65535) == b"unrelated-udp", "allowlist captured ordinary UDP"

        # A selected source IP and protocol must reach the decoder even with
        # different TCP ports. Its explicit port rejection proves broad capture
        # without waiting for a genuine TCP connection to time out.
        other_port = 1 if server_port != 1 else 2
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as injector:
            for process, role, source, destination in (
                    (processes[0], "server", "192.0.2.10", "198.51.100.10"),
                    (processes[1], "client", "198.51.100.10", "192.0.2.10")):
                segment = bytearray(struct.pack("!HHIIBBHHH", other_port, other_port, 1, 0,
                                                0x50, 0x02, 65535, 0, 0))
                pseudo = socket.inet_aton(source) + socket.inet_aton(destination) + struct.pack("!BBH", 0, 6, len(segment))
                struct.pack_into("!H", segment, 16, checksum(pseudo + segment))
                injector.sendto(native_packet(source, destination, 6, segment), (destination, 0))
                marker = (f"Encryption{role.title()}: dropping packet" if encrypted else
                          f"FakeTcpHeader{role.title()}: dropping incoming carrier: "
                          "carrier ports do not match the configured mapping")
                deadline = time.monotonic() + 5
                while marker not in (directory / role / "stdout.log").read_text():
                    process.check_running(role + " exited during broad TCP capture check")
                    assert time.monotonic() < deadline, "selected-peer TCP on other ports did not reach the decoder"
                    time.sleep(0.01)

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
        sequence_ranges = {}
        acknowledgment_ranges = {}
        fixed_acknowledgments = {}
        encrypted_packets = {source: set() for source in seen}
        encrypted_nonces = {}
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
            if encrypted:
                body = carrier[fake_length:]
                assert len(body) >= ENCRYPTION_OVERHEAD + 9, "truncated encrypted UDP carrier"
                assert total - fake_length - 1 - ENCRYPTION_OVERHEAD <= native_mtu
                sequence, acknowledgment = struct.unpack_from("!II", carrier, 4)
                assert carrier[13] == 0x18 and carrier[20:fake_length] == FAKE_OPTIONS
                expected_fake = bytearray(struct.pack("!HHIIBBHHH", *ports, sequence, acknowledgment,
                                                     0x60, 0x18, 65535, 0, 0) + FAKE_OPTIONS)
                struct.pack_into("!H", expected_fake, 16, checksum(pseudo + expected_fake + body))
                assert carrier[:fake_length] == expected_fake, "encryption changed the visible fake TCP template"
                ranges = sequence_ranges.setdefault((source, client_side), {})
                entry = (len(body), packet)
                assert ranges.setdefault(sequence, entry) == entry, "encrypted carriers reused a sequence range"
                nonce_key = (source, body[:24])
                assert encrypted_nonces.setdefault(nonce_key, body) == body, "nonce reused for different encrypted data"
                encrypted_packets[source].add(packet)
                observed_client_ports.add(client_side)
                return
            assert len(carrier) > fake_length, "missing native protocol byte"
            protocol = carrier[fake_length]
            assert protocol == (6 if tcp else 17), "wire protocol byte does not identify the native packet"
            native = carrier[fake_length + 1:]
            assert len(native) >= (20 if tcp else 8), "missing native transport header"
            native_ports = struct.unpack_from("!HH", native)
            native_client, native_server = native_ports if forward else native_ports[::-1]
            assert native_server == native_target, "native header is not immediately after the protocol byte"
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
            initial_sequence = 12345 if forward else 67890
            sequence, acknowledgment = struct.unpack_from("!II", carrier, 4)
            fake_flags = carrier[13]
            allowed_flags = (0x02, 0x05, 0x18) if tcp else (0x07, 0) if tun else (0x18,)
            assert fake_flags in allowed_flags, "fake TCP flags escaped the configured script"
            if tun or tcp:
                # ACK reservations may be ordered differently from sequence
                # reservations across workers; validate each counter separately.
                ranges = acknowledgment_ranges.setdefault((source, client_side), {})
                entry = (1, packet)
                assert ranges.setdefault(acknowledgment, entry) == entry, "different packets reused a fake ACK"
            elif multi_queue:
                assert fixed_acknowledgments.setdefault(source, acknowledgment) == acknowledgment, \
                    "random fake acknowledgment changed within its configured node scope"
            # random_packet permits repeated values, including zero; native
            # units check its random draws. Verify the actual ACK's checksum
            # contribution here without a probabilistic uniqueness assertion.
            if tun:
                assert sequence == initial_sequence, "disabled fake sequence increment changed its configured value"
            else:
                # Check modulo-relative order later: workers may deliver wire
                # packets out of order, and loopback may capture a frame twice.
                ranges = sequence_ranges.setdefault((source, client_side), {})
                control_span = bool(fake_flags & 0x02) + bool(fake_flags & 0x01)
                entry = (len(carrier) - fake_length + control_span, packet)
                assert ranges.setdefault(sequence, entry) == entry, "different packets reused a fake sequence range"
            expected_fake = bytearray(struct.pack("!HHIIBBHHH", *ports, sequence, acknowledgment,
                                                 0x60, fake_flags, 65535, 0, 0) + FAKE_OPTIONS)
            struct.pack_into("!H", expected_fake, 16, checksum(pseudo + expected_fake + bytes((protocol,)) + native))
            assert carrier[:fake_length] == expected_fake, "configured fake TCP header did not reach wire"
            assert total == 20 + 24 + 1 + len(native) and total - 25 <= NATIVE_MTU
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
                assert native == expected_udp and total == 20 + 24 + 1 + 8 + len(payload), \
                    "wire is not exactly IPv4/fake-TCP/protocol/native-UDP/application"
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
                    application.sendto(bytes(1448), destination)
                except OSError as error:
                    assert error.errno == errno.EMSGSIZE, "wrong oversized TUN datagram refusal"
                else:
                    raise AssertionError("TUN MTU admitted an oversized UDP datagram")
            sent, received = bytearray(), bytearray()
            for length in (1, 513, 1400) if tcp else (1, 513, native_mtu - 28):
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
        while not (all(len(packets) == len(requests) for packets in encrypted_packets.values()) if encrypted else
                   tcp_complete() if tcp else
                   seen["192.0.2.10"] == requests and seen["198.51.100.10"] == responses):
            assert time.monotonic() < deadline, "missing native transport wire packets"
            try:
                inspect(wire.recv(65535))
            except TimeoutError:
                continue
        assert observed_client_ports, "no fake TCP carrier was inspected"
        if encrypted:
            for source, payloads in zip(seen, (requests, responses)):
                observed_lengths = Counter(len(packet) - 20 - 24 - ENCRYPTION_OVERHEAD - 1 - 8
                                           for packet in encrypted_packets[source])
                assert observed_lengths == Counter(map(len, payloads)), "encrypted carrier expansion is not exactly 40 bytes"
                for packet in encrypted_packets[source]:
                    for payload in payloads:
                        if len(payload) >= 32:
                            assert payload not in packet[44:], "application payload remained visible in encrypted carrier"
            assert any(len(packet) == 1500 for packet in encrypted_packets["192.0.2.10"]), \
                "encrypted MTU boundary was not exercised"
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
        if tun or tcp:
            assert acknowledgment_ranges, "no incrementing fake acknowledgments were inspected"
            for key, ranges in acknowledgment_ranges.items():
                initial = TCP_ACK_STARTS[0 if key[0] == "192.0.2.10" else 1] if tcp else None
                check_sequence_ranges(ranges, key, initial, field="acknowledgment")
                # Distinct ACK values identify accepted encodings; loopback can
                # capture one packet twice. Script reservations can be reordered
                # relative to ACK/sequence reservations, so compare multisets.
                flags = [packet[(packet[0] & 15) * 4 + 13] for _, packet in ranges.values()]
                if tun:
                    assert len(ranges) == 3, "TUN ACK count did not match the three accepted UDP packets"
                    assert flags.count(0x07) == 1 and flags.count(0) == 2, \
                        "TUN flag script did not advance once and repeat its final empty entry per port"
                else:
                    assert flags.count(0x02) == 1 and flags.count(0x05) == 1 and flags.count(0x18) >= 2, \
                        "TCP flag script did not emit each prefix once then repeat its final entry per port"
        if not tun:
            assert sequence_ranges, "no incrementing fake sequence ranges were inspected"
            node_starts = {}
            for key, ranges in sequence_ranges.items():
                source = key[0]
                expected_initial = (12345 if source == "192.0.2.10" else 67890) if tcp else None
                initial = check_sequence_ranges(ranges, key, expected_initial)
                if multi_queue and not tcp:
                    assert node_starts.setdefault(source, initial) == initial, \
                        "random_node did not use the same starting sequence for every client port"

        if encrypted:
            # Corrupt only the authentication tag, preserving the encrypted
            # protocol and body so downstream validation cannot mask an auth bypass.
            # Repair the visible checksum; the packet line must stay usable afterward.
            damaged = bytearray(next(iter(encrypted_packets["192.0.2.10"])))
            ihl = (damaged[0] & 15) * 4
            damaged[-1] ^= 1
            damaged[ihl + 16:ihl + 18] = bytes(2)
            pseudo = damaged[12:20] + struct.pack("!BBH", 0, 6, len(damaged) - ihl)
            struct.pack_into("!H", damaged, ihl + 16, checksum(pseudo + damaged[ihl:]))
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW) as injector:
                injector.sendto(damaged, ("198.51.100.10", 0))
            backend.settimeout(0.3)
            try:
                backend.recvfrom(65535)
            except TimeoutError:
                pass
            else:
                raise AssertionError("tampered encrypted packet reached the UDP application")
            backend.settimeout(5)
            application.sendto(b"valid-after-authentication-failure", destination)
            actual, peer = backend.recvfrom(65535)
            assert actual == b"valid-after-authentication-failure", "authentication drop broke later packet delivery"
            backend.sendto(b"still-alive", peer)
            assert application.recvfrom(65535)[0] == b"still-alive", "authentication drop closed the packet line"

        for process in reversed(processes):
            process.terminate()
            assert process.wait(timeout=15) in (0, 143), "peer failed orderly shutdown"
        assert "WWCAP" not in iptables("-S", "INPUT"), "capture rules survived shutdown"
        assert "WWCAP_NOTRACK" not in iptables("-t", "raw", "-S", "PREROUTING")
        assert "WWRAW_NOTRACK" not in iptables("-t", "raw", "-S", "OUTPUT")


def main():
    binary = str(Path(sys.argv[1]).resolve())
    options = sys.argv[2:]
    assert set(options) <= {"--tun", "--multi-queue", "--tcp", "--encrypted"}, f"unknown options {options}"
    assert not ("--tun" in options and "--tcp" in options), "TCP mode uses the CTP input fixture"
    assert not ("--encrypted" in options and set(options) & {"--tun", "--tcp", "--multi-queue"}), \
        "encrypted raw mode uses the UDP fixture"
    with RunDirectory(prefix="waterwall-fake-tcp-") as temporary:
        directory = Path(temporary)
        try:
            run(binary, directory, "--tun" in options, "--multi-queue" in options, "--tcp" in options,
                "--encrypted" in options)
        except Exception:
            for log in directory.rglob("stdout.log"):
                print(f"{log}:\n{log.read_text()[-12000:]}", file=sys.stderr)
            raise
    print("Single-IP fake TCP layout/checksums/sequences/acknowledgments, native flow ports, "
          "exact UDP/TCP/TUN request/reply, MTU, "
          "capture exclusions and cleanup passed")


if __name__ == "__main__":
    install_termination_handler()
    main()
