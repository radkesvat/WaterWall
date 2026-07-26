#!/usr/bin/env python3

import ipaddress
import socket
import struct
import time


TUN_NAME = "wwpingdirect0"
OUTER_IDENTIFIER = 4660
INNER_IDENTIFIER = 0x2A2A
INNER_SEQUENCE = 7
INNER_SOURCE = "10.252.30.2"
INNER_DESTINATION = "10.252.30.1"
OUTER_SOURCE = "127.0.0.2"
OUTER_DESTINATION = "127.0.0.1"
RESPONSE_SOURCE = "127.0.0.1"
RESPONSE_DESTINATION = "127.0.0.2"
PAYLOAD = b"waterwall-ping-direct-real-adapters"


def checksum(data):
    if len(data) % 2:
        data += b"\x00"

    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return (~value) & 0xFFFF


def ipv4_packet(source, destination, protocol, payload, identification):
    source_bytes = ipaddress.IPv4Address(source).packed
    destination_bytes = ipaddress.IPv4Address(destination).packed
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        identification,
        0,
        64,
        protocol,
        0,
        source_bytes,
        destination_bytes,
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def icmp_echo(icmp_type, identifier, sequence, payload):
    frame = struct.pack("!BBHHH", icmp_type, 0, 0, identifier, sequence) + payload
    return frame[:2] + struct.pack("!H", checksum(frame)) + frame[4:]


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
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None

    header_len = (packet[0] & 0x0F) * 4
    total_len = struct.unpack_from("!H", packet, 2)[0]
    if header_len < 20 or total_len < header_len or total_len > len(packet):
        return None

    return {
        "source": str(ipaddress.IPv4Address(packet[12:16])),
        "destination": str(ipaddress.IPv4Address(packet[16:20])),
        "protocol": packet[9],
        "payload": packet[header_len:total_len],
    }


def is_expected_response(packet):
    outer = parse_ipv4(packet)
    if (
        outer is None
        or outer["source"] != RESPONSE_SOURCE
        or outer["destination"] != RESPONSE_DESTINATION
        or outer["protocol"] != socket.IPPROTO_ICMP
        or len(outer["payload"]) < 8
    ):
        return False

    outer_type, outer_code, _, outer_identifier, _ = struct.unpack_from("!BBHHH", outer["payload"])
    if outer_type != 8 or outer_code != 0 or outer_identifier != OUTER_IDENTIFIER:
        return False

    inner = parse_ipv4(outer["payload"][8:])
    if (
        inner is None
        or inner["source"] != INNER_DESTINATION
        or inner["destination"] != INNER_SOURCE
        or inner["protocol"] != socket.IPPROTO_ICMP
        or len(inner["payload"]) < 8
    ):
        return False

    inner_type, inner_code, _, inner_identifier, inner_sequence = struct.unpack_from("!BBHHH", inner["payload"])
    return (
        inner_type == 0
        and inner_code == 0
        and inner_identifier == INNER_IDENTIFIER
        and inner_sequence == INNER_SEQUENCE
        and inner["payload"][8:] == PAYLOAD
    )


def main():
    wait_for_tun()

    inner_icmp = icmp_echo(8, INNER_IDENTIFIER, INNER_SEQUENCE, PAYLOAD)
    inner_packet = ipv4_packet(
        INNER_SOURCE,
        INNER_DESTINATION,
        socket.IPPROTO_ICMP,
        inner_icmp,
        0x3101,
    )
    outer_icmp = icmp_echo(8, OUTER_IDENTIFIER, 1, inner_packet)
    request = ipv4_packet(
        OUTER_SOURCE,
        OUTER_DESTINATION,
        socket.IPPROTO_ICMP,
        outer_icmp,
        0x4101,
    )

    receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    receiver.bind((RESPONSE_DESTINATION, 0))
    receiver.settimeout(0.25)

    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    try:
        deadline = time.monotonic() + 10
        next_send = 0
        while time.monotonic() < deadline:
            now = time.monotonic()
            if now >= next_send:
                sender.sendto(request, (OUTER_DESTINATION, 0))
                next_send = now + 0.25

            try:
                packet, _ = receiver.recvfrom(65535)
            except socket.timeout:
                continue

            if is_expected_response(packet):
                print("RawSocket -> PingServer -> TunDevice direct flow verified")
                return
    finally:
        sender.close()
        receiver.close()

    raise RuntimeError("timed out waiting for the wrapped ICMP response")


if __name__ == "__main__":
    main()
