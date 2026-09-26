#!/usr/bin/env python3
"""Exercise Linux TUN offload and raw-IP compatibility in an isolated namespace."""

import errno
import fcntl
import hashlib
import json
import os
import re
import select
import socket
import struct
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor


TUN_NAME = "wwgsolive0"
INJECT_NAME = "wwgsoinj0"
VETH_OUT = "wwgsoout0"
VETH_PEER = "wwgsopeer0"
VETH_OUT_IP = "172.30.82.1"
VETH_PEER_IP = "172.30.82.2"
LOCAL_IP = "10.253.82.1"
DESTINATION_IP = "10.253.82.2"
INJECT_SOURCE_IP = "192.0.2.2"
FINAL_ROUTE_IP = "203.0.113.2"
MTU = 1500
TUNSETIFF = 0x400454CA
TUNSETOFFLOAD = 0x400454D0
TUNSETVNETHDRSZ = 0x400454D8
TUNSETVNETLE = 0x400454DC
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000
IFF_VNET_HDR = 0x4000
TUN_F_CSUM = 0x01
TUN_F_TSO4 = 0x02
PACKET_OUTGOING = 4
IPPROTO_MPTCP = 262
TCP_MD5SIG = 14
TCP_MD5SIG_KEY = b"waterwall-md5-live-key"


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL)


def checksum(data):
    if len(data) & 1:
        data += b"\0"
    total = sum(struct.unpack("!" + "H" * (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def pseudoheader(source, destination, protocol, length):
    return socket.inet_aton(source) + socket.inet_aton(destination) + struct.pack("!BBH", 0, protocol, length)


def ipv4_header(source, destination, protocol, body_length, identification, options=b"", tos=0):
    assert len(options) % 4 == 0
    header_length = 20 + len(options)
    header = bytearray(
        struct.pack(
            "!BBHHHBBH4s4s",
            0x40 | (header_length // 4),
            tos,
            header_length + body_length,
            identification,
            0x4000,
            64,
            protocol,
            0,
            socket.inet_aton(source),
            socket.inet_aton(destination),
        )
        + options
    )
    struct.pack_into("!H", header, 10, checksum(header))
    return bytes(header)


def tcp_record(payload, source_port, sequence, identification, flags=0x18, tcp_options=b"", ip_options=b"",
               source=INJECT_SOURCE_IP, destination=DESTINATION_IP, final_destination=None, gso_size=0,
               deferred=False, urgent_pointer=0, gso_type=None, tos=0):
    assert len(tcp_options) % 4 == 0
    final_destination = final_destination or destination
    tcp_length = 20 + len(tcp_options) + len(payload)
    tcp = bytearray(
        struct.pack("!HHIIBBHHH", source_port, 5678, sequence, 0, ((20 + len(tcp_options)) // 4) << 4,
                    flags, 65535, 0, urgent_pointer)
        + tcp_options + payload
    )
    if deferred:
        # Linux CHECKSUM_PARTIAL stores the uncomplemented pseudoheader sum.
        seed = (~checksum(pseudoheader(source, final_destination, 6, tcp_length))) & 0xFFFF
        struct.pack_into("!H", tcp, 16, seed)
    else:
        struct.pack_into("!H", tcp, 16, checksum(pseudoheader(source, final_destination, 6, tcp_length) + tcp))
    ip = ipv4_header(source, destination, 6, len(tcp), identification, ip_options, tos)
    metadata = struct.pack("<BBHHHH", 1 if deferred else 0, (1 if gso_size else 0) if gso_type is None else gso_type,
                           len(ip) + 20 + len(tcp_options), gso_size, len(ip), 16)
    return metadata + ip + tcp


def udp_record(payload, identification, zero_checksum=False, deferred=False):
    udp = bytearray(struct.pack("!HHHH", 1234, 5679, 8 + len(payload), 0) + payload)
    if deferred:
        seed = (~checksum(pseudoheader(INJECT_SOURCE_IP, DESTINATION_IP, 17, len(udp)))) & 0xFFFF
        struct.pack_into("!H", udp, 6, seed)
    elif not zero_checksum:
        value = checksum(pseudoheader(INJECT_SOURCE_IP, DESTINATION_IP, 17, len(udp)) + udp)
        struct.pack_into("!H", udp, 6, value or 0xFFFF)
    ip = ipv4_header(INJECT_SOURCE_IP, DESTINATION_IP, 17, len(udp), identification)
    metadata = struct.pack("<BBHHHH", 1 if deferred else 0, 0, 0, 0, len(ip), 6)
    return metadata + ip + udp


def icmp_record(identification):
    icmp = bytearray(struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + b"waterwall-gso-icmp")
    struct.pack_into("!H", icmp, 2, checksum(icmp))
    ip = ipv4_header(INJECT_SOURCE_IP, DESTINATION_IP, 1, len(icmp), identification)
    return bytes(10) + ip + icmp


def parse_ipv4(packet):
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    header_length = (packet[0] & 0x0F) * 4
    if header_length < 20 or header_length > len(packet):
        return None
    if struct.unpack_from("!H", packet, 2)[0] != len(packet) or checksum(packet[:header_length]) != 0:
        return None
    return header_length


def packet_capture(device):
    capture = socket.socket(socket.AF_PACKET, socket.SOCK_DGRAM, socket.htons(0x0003))
    capture.bind((device, 0))
    # This privileged test must hold a >2,048-packet burst. SO_RCVBUF alone is
    # capped by net.core.rmem_max (often only 212 KiB), which loses observations
    # even when WaterWall publishes every segment.
    capture.setsockopt(socket.SOL_SOCKET, 33, 8 * 1024 * 1024)  # SO_RCVBUFFORCE
    capture.settimeout(0.2)
    return capture


def has_tcp_option(options, kind):
    offset = 0
    while offset < len(options):
        current = options[offset]
        if current == 0:
            return False
        if current == 1:
            offset += 1
            continue
        if offset + 1 >= len(options):
            return False
        length = options[offset + 1]
        if length < 2 or offset + length > len(options):
            return False
        if current == kind:
            return True
        offset += length
    return False


def set_tcp_md5_key(sock, peer_ip):
    # Linux UAPI struct tcp_md5sig: sockaddr_storage[128], flags, prefix,
    # native-endian key length/ifindex, then an 80-byte binary key area.
    address = struct.pack("=H", socket.AF_INET) + b"\0\0" + socket.inet_aton(peer_ip) + bytes(120)
    option = (address + struct.pack("=BBHi", 0, 0, len(TCP_MD5SIG_KEY), 0)
              + TCP_MD5SIG_KEY.ljust(80, b"\0"))
    assert len(option) == 216
    sock.setsockopt(socket.IPPROTO_TCP, TCP_MD5SIG, option)


def collect(capture, identify, count, timeout=20):
    packets = []
    all_outgoing = 0
    invalid_geometry = 0
    deadline = time.monotonic() + timeout
    while len(packets) < count and time.monotonic() < deadline:
        try:
            packet, address = capture.recvfrom(70000)
        except socket.timeout:
            continue
        if address[2] == PACKET_OUTGOING:
            all_outgoing += 1
            if parse_ipv4(packet) is None:
                invalid_geometry += 1
            if identify(packet):
                packets.append(packet)
    if len(packets) != count:
        stats = capture.getsockopt(263, 6, 8)
        packet_count, drops = struct.unpack("II", stats)
        sequences = sorted(struct.unpack_from("!I", packet, ((packet[0] & 0x0F) * 4) + 4)[0]
                           for packet in packets if packet[9] == 6)
        print(f"CAPTURE_STATS matched={len(packets)} expected={count} outgoing={all_outgoing} "
              f"invalid_geometry={invalid_geometry} socket_packets={packet_count} socket_drops={drops} "
              f"first_seq={sequences[:4]} last_seq={sequences[-4:]}", file=sys.stderr, flush=True)
    assert len(packets) == count, f"expected {count} packets, captured {len(packets)}"
    return packets


def assert_tcp_segment(packet, source_port, sequence, payload, identification, final_destination, options,
                       final_segment, first_segment, flags, urgent_pointer):
    ip_length = parse_ipv4(packet)
    assert ip_length is not None and len(packet) <= MTU, "segmented IP packet invalid or above MTU"
    assert packet[9] == 6 and packet[12:16] == socket.inet_aton(INJECT_SOURCE_IP)
    assert packet[16:20] == socket.inet_aton(DESTINATION_IP)
    assert struct.unpack_from("!H", packet, 4)[0] == identification
    tcp = packet[ip_length:]
    tcp_header_length = (tcp[12] >> 4) * 4
    assert tcp_header_length == 20 + len(options)
    assert tcp[20:tcp_header_length] == options, "TCP options changed during segmentation"
    assert struct.unpack_from("!H", tcp, 0)[0] == source_port
    assert struct.unpack_from("!I", tcp, 4)[0] == sequence
    assert tcp[tcp_header_length:] == payload, "segment payload or order changed"
    assert bool(tcp[13] & 0x08) == (final_segment and bool(flags & 0x08)), "PSH placement changed"
    assert bool(tcp[13] & 0x01) == (final_segment and bool(flags & 0x01)), "FIN placement changed"
    assert bool(tcp[13] & 0x80) == (first_segment and bool(flags & 0x80)), "CWR placement changed"
    assert bool(tcp[13] & 0x20) == bool(flags & 0x20), "URG flag changed"
    assert struct.unpack_from("!H", tcp, 18)[0] == urgent_pointer, "URG pointer changed"
    assert checksum(pseudoheader(INJECT_SOURCE_IP, final_destination, 6, len(tcp)) + tcp) == 0, \
        "segmented TCP checksum does not cover the final destination"


def collect_tcp_segments(capture, injector, payload, port, sequence, identification, gso_size, tcp_options=b"",
                         ip_options=b"", final_destination=None, flags=0x18, urgent_pointer=0, gso_type=None, tos=0,
                         fingerprint=False):
    count = (len(payload) + gso_size - 1) // gso_size
    record = tcp_record(payload, port, sequence, identification, tcp_options=tcp_options, ip_options=ip_options,
                        final_destination=final_destination, gso_size=gso_size, deferred=True, flags=flags,
                        urgent_pointer=urgent_pointer, gso_type=gso_type, tos=tos)
    assert injector.write(record) == len(record)

    def identify(packet):
        ip_length = parse_ipv4(packet)
        return (ip_length is not None and packet[9] == 6 and packet[12:16] == socket.inet_aton(INJECT_SOURCE_IP)
                and len(packet) >= ip_length + 20 and struct.unpack_from("!H", packet, ip_length)[0] == port)

    packets = collect(capture, identify, count)
    seen = set()
    for packet in packets:
        ip_length = (packet[0] & 0x0F) * 4
        offset = struct.unpack_from("!I", packet, ip_length + 4)[0] - sequence
        assert offset >= 0 and offset % gso_size == 0 and offset < len(payload)
        index = offset // gso_size
        assert index not in seen, "duplicate output segment"
        seen.add(index)
        part = payload[offset:offset + gso_size]
        assert_tcp_segment(packet, port, sequence + offset, part, identification + index,
                           final_destination or DESTINATION_IP, tcp_options, index == count - 1,
                           index == 0, flags, urgent_pointer)
        if ip_options:
            assert packet[20:20 + len(ip_options)] == ip_options, "IPv4 options changed during segmentation"
    assert len(seen) == count
    if fingerprint:
        ordered = sorted(packets, key=lambda packet: struct.unpack_from("!I", packet, (packet[0] & 0x0F) * 4 + 4)[0])
        wire_bytes = b"".join(struct.pack("!H", len(packet)) + packet for packet in ordered)
        return {"segments": count, "sha256": hashlib.sha256(wire_bytes).hexdigest()}
    return count


def collect_ordinary(capture, injector, record, identification, protocol, expected_body=None, source_port=None,
                     expect_udp_zero=False):
    assert injector.write(record) == len(record)

    def identify(packet):
        ip_length = parse_ipv4(packet)
        return (ip_length is not None and packet[9] == protocol and packet[12:16] == socket.inet_aton(INJECT_SOURCE_IP)
                and packet[16:20] == socket.inet_aton(DESTINATION_IP)
                and struct.unpack_from("!H", packet, 4)[0] == identification)

    packet = collect(capture, identify, 1, timeout=5)[0]
    ip_length = (packet[0] & 0x0F) * 4
    body = packet[ip_length:]
    if expected_body is not None:
        assert body == expected_body, "ordinary packet body changed"
    if protocol == 6:
        assert struct.unpack_from("!H", body)[0] == source_port
        assert checksum(pseudoheader(INJECT_SOURCE_IP, DESTINATION_IP, 6, len(body)) + body) == 0
    elif protocol == 17:
        if expect_udp_zero:
            assert struct.unpack_from("!H", body, 6)[0] == 0
        else:
            assert checksum(pseudoheader(INJECT_SOURCE_IP, DESTINATION_IP, 17, len(body)) + body) == 0
    else:
        assert checksum(body) == 0
    return packet


def open_injector():
    tun_fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    flags = IFF_TUN | IFF_NO_PI | IFF_VNET_HDR
    fcntl.ioctl(tun_fd, TUNSETIFF, struct.pack("16sH22x", INJECT_NAME.encode(), flags))
    fcntl.ioctl(tun_fd, TUNSETVNETHDRSZ, struct.pack("I", 10))
    fcntl.ioctl(tun_fd, TUNSETVNETLE, struct.pack("I", 1))
    fcntl.ioctl(tun_fd, TUNSETOFFLOAD, TUN_F_CSUM | TUN_F_TSO4)
    run("ip", "addr", "add", "192.0.2.1/24", "dev", INJECT_NAME)
    run("ip", "link", "set", INJECT_NAME, "up")
    run("sysctl", "-qw", "net.ipv4.ip_forward=1")
    run("sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")
    run("sysctl", "-qw", f"net.ipv4.conf.{INJECT_NAME}.rp_filter=0")
    run("sysctl", "-qw", "net.ipv4.conf.all.accept_source_route=1")
    run("sysctl", "-qw", f"net.ipv4.conf.{INJECT_NAME}.accept_source_route=1")
    return tun_fd


class PeerNamespace:
    def __enter__(self):
        self.holder = subprocess.Popen(["unshare", "-n", "--", "sleep", "120"])
        original = os.readlink("/proc/self/ns/net")
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self.holder.poll() is not None:
                raise RuntimeError("peer namespace holder exited")
            if os.readlink(f"/proc/{self.holder.pid}/ns/net") != original:
                break
            time.sleep(0.01)
        else:
            raise RuntimeError("peer namespace was not entered")

        run("ip", "link", "add", VETH_OUT, "type", "veth", "peer", "name", VETH_PEER)
        run("ip", "link", "set", VETH_PEER, "netns", str(self.holder.pid))
        run("ip", "addr", "add", f"{VETH_OUT_IP}/30", "dev", VETH_OUT)
        run("ip", "link", "set", VETH_OUT, "up")
        self.peer_run("ip", "link", "set", "lo", "up")
        self.peer_run("ip", "addr", "add", f"{VETH_PEER_IP}/30", "dev", VETH_PEER)
        self.peer_run("ip", "addr", "add", f"{DESTINATION_IP}/32", "dev", VETH_PEER)
        self.peer_run("ip", "link", "set", VETH_PEER, "up")
        self.peer_run("ip", "route", "add", f"{LOCAL_IP}/32", "via", VETH_OUT_IP, "dev", VETH_PEER)
        run("ip", "route", "add", f"{DESTINATION_IP}/32", "via", VETH_PEER_IP, "dev", VETH_OUT,
            "table", "100")
        run("sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")
        run("sysctl", "-qw", f"net.ipv4.conf.{VETH_OUT}.rp_filter=0")
        return self

    def peer_run(self, *args):
        run("nsenter", "-t", str(self.holder.pid), "-n", *args)

    def server_command(self, protocol, port, amount, md5):
        return ["nsenter", "-t", str(self.holder.pid), "-n", sys.executable, __file__, "--server",
                str(protocol), str(port), str(amount), "md5" if md5 else "plain"]

    def __exit__(self, exc_type, exc, traceback):
        subprocess.run(["ip", "route", "delete", f"{DESTINATION_IP}/32", "via", VETH_PEER_IP,
                        "dev", VETH_OUT, "table", "100"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "delete", VETH_OUT], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.holder.terminate()
        try:
            self.holder.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self.holder.kill()
            self.holder.wait(timeout=3)


def receive_tcp(protocol, port, amount, md5):
    marker = bytes((index * 17 + 3) & 255 for index in range(65536))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM, protocol) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((DESTINATION_IP, port))
        if md5:
            set_tcp_md5_key(server, LOCAL_IP)
        server.listen(1)
        server.settimeout(15)
        print("READY", flush=True)
        accepted, _ = server.accept()
        with accepted:
            accepted.settimeout(15)
            position = 0
            while position < amount:
                data = accepted.recv(min(65536, amount - position))
                assert data, "TCP transfer ended before all bytes arrived"
                remaining = data
                while remaining:
                    index = position % len(marker)
                    part = remaining[:len(marker) - index]
                    assert part == marker[index:index + len(part)], "TCP payload changed"
                    position += len(part)
                    remaining = remaining[len(part):]
            print(f"BYTES {position}", flush=True)


class TunInjector:
    def __init__(self, fd):
        self.fd = fd

    def write(self, record):
        return os.write(self.fd, record)


def transfer_tcp(peer, protocol, port, amount, capture_tun, md5=False, start_barrier=None):
    marker = bytes((index * 17 + 3) & 255 for index in range(65536))
    server = subprocess.Popen(peer.server_command(protocol, port, amount, md5), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True)
    ready, _, _ = select.select([server.stdout], [], [], 5)
    if not ready or server.stdout.readline().strip() != "READY":
        stderr = server.stderr.read() if server.poll() is not None else "server did not announce readiness"
        server.kill()
        server.wait()
        raise AssertionError(stderr)
    try:
        if start_barrier is not None:
            start_barrier.wait(timeout=15)
        begin = time.monotonic()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM, protocol) as client:
            client.settimeout(15)
            client.bind((LOCAL_IP, 0))
            if md5:
                set_tcp_md5_key(client, DESTINATION_IP)
            client.connect((DESTINATION_IP, port))
            remaining = amount
            while remaining:
                part = marker[:min(remaining, len(marker))]
                client.sendall(part)
                remaining -= len(part)
            client.shutdown(socket.SHUT_WR)
        stdout, stderr = server.communicate(timeout=16)
        assert server.returncode == 0 and f"BYTES {amount}" in stdout, (server.returncode, stdout, stderr)
        elapsed = time.monotonic() - begin
    except Exception:
        if capture_tun is not None:
            capture_tun.setblocking(False)
            for _ in range(8):
                try:
                    packet, address = capture_tun.recvfrom(70000)
                except BlockingIOError:
                    break
                print(f"TUN_CAPTURE length={len(packet)} address={address} first={packet[:80].hex()}",
                      file=sys.stderr, flush=True)
        raise
    finally:
        if server.poll() is None:
            server.kill()
            server.wait()

    oversized = 0
    mptcp_seen = False
    md5_seen = False
    if capture_tun is not None:
        capture_tun.setblocking(False)
        while True:
            try:
                packet, address = capture_tun.recvfrom(70000)
            except BlockingIOError:
                break
            ip_length = parse_ipv4(packet)
            if (address[2] != PACKET_OUTGOING or ip_length is None or packet[9] != 6):
                continue
            if packet[12:16] != socket.inet_aton(LOCAL_IP) or packet[16:20] != socket.inet_aton(DESTINATION_IP):
                continue
            oversized += len(packet) > MTU
            tcp = packet[ip_length:]
            tcp_header_length = (tcp[12] >> 4) * 4
            if 20 <= tcp_header_length <= len(tcp):
                mptcp_seen |= has_tcp_option(tcp[20:tcp_header_length], 30)
                md5_seen |= has_tcp_option(tcp[20:tcp_header_length], 19)
    return {"bytes": amount, "elapsed_seconds": round(elapsed, 6), "tun_oversized_records": oversized,
            "mptcp_option_seen": mptcp_seen, "md5_option_seen": md5_seen}


def transfer_tcp_flows(peer, amount, flow_count):
    starts = []
    barrier = threading.Barrier(flow_count, action=lambda: starts.append(time.monotonic()))
    with ThreadPoolExecutor(max_workers=flow_count) as executor:
        futures = [executor.submit(transfer_tcp, peer, socket.IPPROTO_TCP, 24682 + index,
                                   amount, None, start_barrier=barrier)
                   for index in range(flow_count)]
        results = [future.result() for future in futures]
    return {"bytes": sum(result["bytes"] for result in results),
            "elapsed_seconds": round(time.monotonic() - starts[0], 6), "flows": flow_count}


def wait_for_tun(mode):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        result = subprocess.run(["ip", "-d", "link", "show", "dev", TUN_NAME], capture_output=True, text=True)
        if result.returncode == 0 and "UP" in result.stdout and "vnet_hdr" in result.stdout:
            enabled = mode == "default"
            assert f"vnet_hdr {'on' if enabled else 'off'}" in result.stdout, result.stdout
            reported = re.search(r"\bgso_max_segs\s+(\d+)\b", result.stdout)
            return int(reported.group(1)) if reported else None
        time.sleep(0.05)
    raise AssertionError("WaterWall TUN did not become ready")


def probe_mode(peer, mode, result_path):
    interface_gso_max_segs = wait_for_tun(mode)
    benchmark = os.environ.get("WATERWALL_GSO_BENCHMARK") == "1"
    benchmark_flows = 1
    if benchmark:
        raw_flows = os.environ.get("WATERWALL_GSO_BENCHMARK_FLOWS", "1")
        assert re.fullmatch(r"[1-9][0-9]?", raw_flows) and int(raw_flows) <= 16, \
            "WATERWALL_GSO_BENCHMARK_FLOWS must be an integer from 1 to 16"
        benchmark_flows = int(raw_flows)
    transfer_size = 32 * 1024 * 1024 if benchmark else 1024 * 1024
    capture_tun = None if benchmark else packet_capture(TUN_NAME)
    try:
        with packet_capture(VETH_OUT) as debug_lo:
            try:
                tcp = (transfer_tcp_flows(peer, transfer_size, benchmark_flows)
                       if benchmark and benchmark_flows > 1 else
                       transfer_tcp(peer, socket.IPPROTO_TCP, 24682, transfer_size, capture_tun))
            except Exception:
                debug_lo.setblocking(False)
                for _ in range(40):
                    try:
                        packet, address = debug_lo.recvfrom(70000)
                    except BlockingIOError:
                        break
                    print(f"VETH_CAPTURE length={len(packet)} address={address} first={packet[:80].hex()}",
                          file=sys.stderr, flush=True)
                subprocess.run(["ip", "route", "get", DESTINATION_IP, "mark", "99"], check=False)
                subprocess.run(["ip", "rule", "show"], check=False)
                raise
    finally:
        if capture_tun is not None:
            capture_tun.close()

    result = {"mode": mode, "local_tcp": tcp, "interface_gso_max_segs": interface_gso_max_segs}
    if not benchmark:
        assert (tcp["tun_oversized_records"] > 0) == (mode == "default"), \
            "local TCP offload did not match the selected TUN framing"
    if not benchmark:
        with packet_capture(TUN_NAME) as md5_capture:
            result["tcp_md5"] = transfer_tcp(peer, socket.IPPROTO_TCP, 24684, 64 * 1024, md5_capture, md5=True)
            assert result["tcp_md5"]["md5_option_seen"], "signed TCP traffic did not carry TCP-MD5"
            assert result["tcp_md5"]["tun_oversized_records"] == 0, "Linux unexpectedly used GSO for TCP-MD5"
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM, IPPROTO_MPTCP):
                pass
        except OSError as exc:
            if exc.errno not in (errno.EPROTONOSUPPORT, errno.ENOPROTOOPT, errno.EAFNOSUPPORT):
                raise
            result["mptcp"] = "kernel protocol unavailable"
        else:
            with packet_capture(TUN_NAME) as mptcp_capture:
                result["mptcp"] = transfer_tcp(peer, IPPROTO_MPTCP, 24683, 256 * 1024, mptcp_capture)
                assert result["mptcp"]["mptcp_option_seen"], "MPTCP traffic did not carry an MPTCP option"

    injector_fd = open_injector()
    injector = TunInjector(injector_fd)
    try:
        with packet_capture(VETH_OUT) as capture:
            comparison_payload = bytes((index * 7 + 3) & 255 for index in range(120))
            result["kernel_comparison"] = collect_tcp_segments(
                capture, injector, comparison_payload, 1240, 700000, 7000, 40, fingerprint=True)
            if mode == "default":
                large_payload = bytes((index * 11 + 7) & 255 for index in range(2051 * 8))
                unknown_option = bytes([253, 4, 0x12, 0x34])
                result["small_mss_segments"] = collect_tcp_segments(
                    capture, injector, large_payload,
                    1234, 100000, 100, 8, tcp_options=unknown_option)
                source_route = bytes([131, 7, 4]) + socket.inet_aton(FINAL_ROUTE_IP) + b"\0"
                result["source_route_segments"] = collect_tcp_segments(
                    capture, injector, bytes(range(100)),
                    1235, 200000, 3000, 8, ip_options=source_route, final_destination=FINAL_ROUTE_IP)
                # A DSS mapping covering the entire aggregate must be copied intact.
                mptcp_dss = bytes([30, 18, 0x20, 0x0C]) + struct.pack("!QIH", 5000, 0, 120) + b"\x01\x01"
                result["mptcp_dss_segments"] = collect_tcp_segments(
                    capture, injector, bytes(range(120)),
                    1236, 300000, 4000, 40, tcp_options=mptcp_dss)
                result["urgent_gso_segments"] = collect_tcp_segments(
                    capture, injector, bytes(range(80)), 1238, 500000, 5100, 8,
                    flags=0x30, urgent_pointer=4)
                # TSO_ECN is not advertised. Linux normalizes this injected
                # GSO+ECN record before the WaterWall TUN reader receives it.
                result["kernel_normalized_ecn_segments"] = collect_tcp_segments(
                    capture, injector, bytes(range(120)), 1239, 600000, 5200, 40,
                    flags=0x98, gso_type=0x81, tos=2)
            else:
                result["kernel_normalized_segments"] = collect_tcp_segments(
                    capture, injector, bytes(range(120)),
                    1237, 400000, 5000, 40)

            ordinary_cases = [
                ("syn", tcp_record(b"", 1301, 1, 6001, flags=0x02), 6001, 6, 1301),
                ("rst", tcp_record(b"", 1302, 2, 6002, flags=0x14), 6002, 6, 1302),
                ("urg", tcp_record(b"urgent!", 1303, 3, 6003, flags=0x30, urgent_pointer=4), 6003, 6, 1303),
                ("md5", tcp_record(b"data", 1304, 4, 6004, tcp_options=b"\x01\x01\x13\x12" + b"M" * 16),
                 6004, 6, 1304),
                ("ao", tcp_record(b"data", 1305, 5, 6005, tcp_options=b"\x1d\x10\x01\x01" + b"A" * 12),
                 6005, 6, 1305),
                ("unknown", tcp_record(b"data", 1306, 6, 6006, tcp_options=b"\xfd\x04\x12\x34"),
                 6006, 6, 1306),
                ("ecn_ordinary", tcp_record(b"ect", 1307, 7, 6010, flags=0x10, tos=2), 6010, 6, 1307),
                ("syn_gso_normalized", tcp_record(b"", 1308, 8, 6011, flags=0x02, gso_size=8, deferred=True),
                 6011, 6, 1308),
                ("rst_gso_normalized", tcp_record(b"", 1309, 9, 6012, flags=0x04, gso_size=8, deferred=True),
                 6012, 6, 1309),
                ("udp_zero", udp_record(b"zero", 6007, zero_checksum=True), 6007, 17, None),
                ("udp_deferred", udp_record(b"deferred", 6008, deferred=True), 6008, 17, None),
                ("icmp", icmp_record(6009), 6009, 1, None),
            ]
            for name, record, identification, protocol, port in ordinary_cases:
                body = record[10 + ((record[10] & 0x0F) * 4):]
                if name in ("udp_deferred", "syn_gso_normalized", "rst_gso_normalized"):
                    body = None
                packet = collect_ordinary(capture, injector,
                                          record, identification, protocol, body, port, name == "udp_zero")
                if name == "udp_deferred":
                    assert struct.unpack_from("!H", packet, 20 + 6)[0] != 0
                if name == "ecn_ordinary":
                    assert packet[1] & 0x03 == 2, "ECT bits changed"
                result[name] = "passed"
    finally:
        os.close(injector_fd)
    with open(result_path, "w", encoding="utf-8") as stream:
        json.dump(result, stream)


def main(mode, result_path):
    with PeerNamespace() as peer:
        probe_mode(peer, mode, result_path)


if __name__ == "__main__":
    if sys.argv[1] == "--server":
        receive_tcp(int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]), sys.argv[5] == "md5")
    else:
        main(sys.argv[1], sys.argv[2])
