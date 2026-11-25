#!/usr/bin/env python3
"""Verify PingServer through RawSocket and TunDevice on namespace loopback."""

import ipaddress
import socket
import struct
import time


TUN_NAME = "wwpingdirect0"
WIRE_PEER = "127.0.0.2"
WIRE_SERVER = "127.0.0.1"
ECHO_IDENTIFIER = 0x2A2A
IPV4_HEADER_LENGTH = 20
ICMP_HEADER_LENGTH = 8
TRAILER_LENGTH = 2
CARRIER_OVERHEAD = ICMP_HEADER_LENGTH + TRAILER_LENGTH
MAX_CARRIER = 1500
MAX_NATIVE = MAX_CARRIER - CARRIER_OVERHEAD
CLIENT_ROLE = 1
SERVER_ROLE = 2


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def ipv4_packet(source, destination, icmp, identification, ttl):
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0x2E,
        IPV4_HEADER_LENGTH + len(icmp),
        identification,
        0x4000,
        ttl,
        socket.IPPROTO_ICMP,
        0,
        ipaddress.IPv4Address(source).packed,
        ipaddress.IPv4Address(destination).packed,
    )
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:] + icmp


def icmp_packet(type_number, code, payload, identifier=0, sequence=0):
    message = struct.pack("!BBHHH", type_number, code, 0, identifier, sequence) + payload
    return message[:2] + struct.pack("!H", checksum(message)) + message[4:]


def peer_carrier(payload, sequence, role=CLIENT_ROLE, type_number=253, code=17):
    native_echo = icmp_packet(8, 0, payload, ECHO_IDENTIFIER, sequence)
    trailer = bytes([socket.IPPROTO_ICMP, role])
    carrier = icmp_packet(type_number, code, native_echo + trailer)
    return ipv4_packet(WIRE_PEER, WIRE_SERVER, carrier, 0x42A0 + sequence, 63)


def wait_for_tun():
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            socket.if_nametoindex(TUN_NAME)
            time.sleep(0.25)
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for {TUN_NAME}")


def parse_ipv4(packet):
    if len(packet) < IPV4_HEADER_LENGTH or packet[0] >> 4 != 4:
        raise RuntimeError("invalid IPv4 packet")
    header_len = (packet[0] & 0x0F) * 4
    total_len = struct.unpack_from("!H", packet, 2)[0]
    if not IPV4_HEADER_LENGTH <= header_len <= 60 or total_len != len(packet) or total_len < header_len:
        raise RuntimeError("invalid IPv4 packet length")
    if checksum(packet[:header_len]) != 0 or packet[9] != socket.IPPROTO_ICMP:
        raise RuntimeError("invalid IPv4 checksum or packet protocol")
    if struct.unpack_from("!H", packet, 6)[0] & 0x3FFF:
        raise RuntimeError("unexpected fragmentation")
    return packet[header_len:]


def server_carrier(packet):
    if len(packet) < IPV4_HEADER_LENGTH:
        return None
    if (
        packet[12:16] != ipaddress.IPv4Address(WIRE_SERVER).packed
        or packet[16:20] != ipaddress.IPv4Address(WIRE_PEER).packed
    ):
        return None

    message = parse_ipv4(packet)
    if len(packet) > MAX_CARRIER or len(message) < CARRIER_OVERHEAD:
        raise RuntimeError("server carrier has invalid length")
    if message[:2] != bytes([254, 66]) or checksum(message) != 0:
        raise RuntimeError("server carrier lost configured type/code or ICMP checksum")
    if message[4:ICMP_HEADER_LENGTH] != bytes(4):
        raise RuntimeError("server carrier has nonzero ICMP header bytes 4 through 7")
    if message[-TRAILER_LENGTH:] != bytes([socket.IPPROTO_ICMP, SERVER_ROLE]):
        raise RuntimeError("server carrier has the wrong saved protocol or sender role")
    return len(packet), message[ICMP_HEADER_LENGTH:-TRAILER_LENGTH]


def receive_carrier(receiver, timeout):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            packet, _ = receiver.recvfrom(65535)
        except socket.timeout:
            continue
        carrier = server_carrier(packet)
        if carrier is not None:
            return carrier
    return None


def require_echo_reply(carrier, sequence, payload):
    if carrier is None:
        raise RuntimeError(f"server did not return native Echo Reply {sequence}")
    wire_length, message = carrier
    expected = icmp_packet(0, 0, payload, ECHO_IDENTIFIER, sequence)
    if wire_length != IPV4_HEADER_LENGTH + len(expected) + CARRIER_OVERHEAD:
        raise RuntimeError("server carrier has wrong encapsulation overhead")
    if message != expected:
        raise RuntimeError("PingServer changed the returned native Echo Reply")


def main():
    wait_for_tun()
    payload = b"waterwall-ping-direct-real-adapters"
    maximum = bytes(i & 0xFF for i in range(MAX_NATIVE - IPV4_HEADER_LENGTH - ICMP_HEADER_LENGTH))

    with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as receiver, socket.socket(
        socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW
    ) as sender:
        receiver.bind((WIRE_PEER, 0))
        receiver.settimeout(0.15)
        sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        peer = (WIRE_SERVER, 0)

        sender.sendto(peer_carrier(payload, 7), peer)
        require_echo_reply(receive_carrier(receiver, 3), 7, payload)

        at_limit = peer_carrier(maximum, 8)
        if len(at_limit) != MAX_CARRIER:
            raise RuntimeError("maximum fixture has the wrong size")
        sender.sendto(at_limit, peer)
        require_echo_reply(receive_carrier(receiver, 3), 8, maximum)

        sender.sendto(peer_carrier(payload, 9, role=SERVER_ROLE, type_number=0, code=0), peer)
        if receive_carrier(receiver, 0.35) is not None:
            raise RuntimeError("reflected server-role frame reached the native interface")
        sender.sendto(peer_carrier(payload, 9, type_number=0, code=0), peer)
        require_echo_reply(receive_carrier(receiver, 3), 9, payload)

        oversized = peer_carrier(maximum + b"x", 10)
        if len(oversized) != MAX_CARRIER + 1:
            raise RuntimeError("oversized fixture has the wrong size")
        sender.sendto(oversized, peer)
        if receive_carrier(receiver, 0.35) is not None:
            raise RuntimeError("oversized native packet escaped the carrier ceiling")

    print("RawSocket -> IpOverrider -> PingServer -> TunDevice ICMPv4 roundtrip verified")


if __name__ == "__main__":
    main()
