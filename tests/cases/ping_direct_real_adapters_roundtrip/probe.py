#!/usr/bin/env python3

import ipaddress
import socket
import struct
import time


TUN_NAME = "wwpingdirect0"
PEER_IDENTIFIER = 4660
SERVER_IDENTIFIER = 4661
INNER_IDENTIFIER = 0x2A2A
INNER_SEQUENCE = 7
INNER_SOURCE = "10.252.30.2"
INNER_DESTINATION = "10.252.30.1"
OUTER_SOURCE = "127.0.0.2"
OUTER_DESTINATION = "127.0.0.1"
PAYLOAD = b"waterwall-ping-direct-real-adapters"
REQUEST_TOS = 0x2E
SERVER_TTL = 64
IP_DF = 0x4000


def checksum(data):
    if len(data) % 2:
        data += b"\x00"

    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return (~value) & 0xFFFF


def ipv4_packet(source, destination, protocol, payload, identification, tos=0, ttl=64, flags_offset=0):
    source_bytes = ipaddress.IPv4Address(source).packed
    destination_bytes = ipaddress.IPv4Address(destination).packed
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        tos,
        20 + len(payload),
        identification,
        flags_offset,
        ttl,
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
    if header_len != 20 or total_len != len(packet) or total_len < header_len:
        return None
    if checksum(packet[:header_len]) != 0:
        return None

    flags_offset = struct.unpack_from("!H", packet, 6)[0]
    return {
        "source": str(ipaddress.IPv4Address(packet[12:16])),
        "destination": str(ipaddress.IPv4Address(packet[16:20])),
        "tos": packet[1],
        "identification": struct.unpack_from("!H", packet, 4)[0],
        "flags_offset": flags_offset,
        "ttl": packet[8],
        "protocol": packet[9],
        "payload": packet[header_len:total_len],
    }


def parse_icmp(payload):
    if len(payload) < 8 or checksum(payload) != 0:
        return None
    icmp_type, code, _, identifier, sequence = struct.unpack_from("!BBHHH", payload)
    return {
        "type": icmp_type,
        "code": code,
        "identifier": identifier,
        "sequence": sequence,
        "payload": payload[8:],
    }


def parse_immediate_reply(packet, expected_request_icmp):
    outer = parse_ipv4(packet)
    if outer is None:
        return None
    if outer["source"] != OUTER_DESTINATION or outer["destination"] != OUTER_SOURCE:
        return None
    if outer["protocol"] != socket.IPPROTO_ICMP:
        return None

    icmp = parse_icmp(outer["payload"])
    if icmp is None or icmp["type"] != 0 or icmp["code"] != 0:
        return None

    expected = parse_icmp(expected_request_icmp)
    if expected is None:
        raise RuntimeError("test built an invalid Echo Request")
    if icmp["identifier"] != expected["identifier"] or icmp["sequence"] != expected["sequence"]:
        return None

    if icmp["payload"] != expected_request_icmp[8:]:
        raise RuntimeError("Echo Reply payload does not exactly mirror the Echo Request")
    if outer["tos"] != REQUEST_TOS or outer["ttl"] != SERVER_TTL:
        raise RuntimeError("Echo Reply TOS/TTL policy is wrong")
    if outer["flags_offset"] != 0:
        raise RuntimeError("Echo Reply must clear DF/MF/fragment offset")
    return outer, icmp


def parse_server_request(packet):
    outer = parse_ipv4(packet)
    if outer is None:
        return None
    if outer["source"] != OUTER_DESTINATION or outer["destination"] != OUTER_SOURCE:
        return None
    if outer["protocol"] != socket.IPPROTO_ICMP:
        return None

    icmp = parse_icmp(outer["payload"])
    if icmp is None or icmp["type"] != 8 or icmp["code"] != 0:
        return None
    if icmp["identifier"] != SERVER_IDENTIFIER:
        return None
    if outer["tos"] != 0 or outer["ttl"] != SERVER_TTL:
        raise RuntimeError("server-originated Echo Request has wrong TOS/TTL")
    if outer["identification"] != 0 or outer["flags_offset"] != IP_DF:
        raise RuntimeError("server-originated Echo Request does not use the documented DF/IPv4-ID policy")

    inner = parse_ipv4(icmp["payload"])
    if (
        inner is None
        or inner["source"] != INNER_DESTINATION
        or inner["destination"] != INNER_SOURCE
        or inner["protocol"] != socket.IPPROTO_ICMP
    ):
        raise RuntimeError("server-originated Echo Request does not carry the inner Echo Reply")
    inner_icmp = parse_icmp(inner["payload"])
    if inner_icmp is None or inner_icmp["type"] != 0 or inner_icmp["code"] != 0:
        raise RuntimeError("inner Echo Reply was not preserved")
    return outer, icmp, inner_icmp


def make_peer_request(outer_sequence, inner_sequence, payload, identification):
    inner_icmp = icmp_echo(8, INNER_IDENTIFIER, inner_sequence, payload)
    inner_packet = ipv4_packet(
        INNER_SOURCE,
        INNER_DESTINATION,
        socket.IPPROTO_ICMP,
        inner_icmp,
        0x3100 + inner_sequence,
    )
    request_icmp = icmp_echo(8, PEER_IDENTIFIER, outer_sequence, inner_packet)
    request = ipv4_packet(
        OUTER_SOURCE,
        OUTER_DESTINATION,
        socket.IPPROTO_ICMP,
        request_icmp,
        identification,
        tos=REQUEST_TOS,
    )
    return request_icmp, request


def send_acknowledgement(sender, server_icmp, identification):
    acknowledgement_icmp = icmp_echo(
        0,
        server_icmp["identifier"],
        server_icmp["sequence"],
        server_icmp["payload"],
    )
    acknowledgement = ipv4_packet(
        OUTER_SOURCE,
        OUTER_DESTINATION,
        socket.IPPROTO_ICMP,
        acknowledgement_icmp,
        identification,
    )
    sender.sendto(acknowledgement, (OUTER_DESTINATION, 0))


def main():
    wait_for_tun()

    request1_icmp, request1 = make_peer_request(1, INNER_SEQUENCE, PAYLOAD, 0x4101)
    second_payload = PAYLOAD + b"-second"
    request2_icmp, request2 = make_peer_request(2, INNER_SEQUENCE + 1, second_payload, 0x4102)

    receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    receiver.bind((OUTER_SOURCE, 0))
    receiver.settimeout(0.25)

    sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sender.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    try:
        sender.sendto(request1, (OUTER_DESTINATION, 0))

        deadline = time.monotonic() + 10
        immediate_replies = []
        server_sequences = []
        duplicate_sent = False
        while time.monotonic() < deadline:
            try:
                packet, _ = receiver.recvfrom(65535)
            except socket.timeout:
                continue

            reply = parse_immediate_reply(packet, request1_icmp)
            if reply is not None:
                immediate_replies.append(reply)
                if not duplicate_sent:
                    sender.sendto(request1, (OUTER_DESTINATION, 0))
                    duplicate_sent = True
                if len(immediate_replies) > 2:
                    raise RuntimeError("peer request received more replies than requests sent")
            else:
                server_request = parse_server_request(packet)
                if server_request is None:
                    continue
                if not immediate_replies:
                    raise RuntimeError("observed server data request before the immediate Echo Reply")

                _, server_icmp, inner_icmp = server_request
                if inner_icmp["identifier"] != INNER_IDENTIFIER or inner_icmp["sequence"] != INNER_SEQUENCE:
                    raise RuntimeError("first server request did not carry the expected inner Echo Reply")
                if inner_icmp["payload"] != PAYLOAD:
                    raise RuntimeError("first server request altered the inner Echo Reply payload")
                server_sequences.append(server_icmp["sequence"])
                if len(server_sequences) > 1:
                    raise RuntimeError("duplicate peer request delivered its inner packet more than once")
                send_acknowledgement(sender, server_icmp, 0x4201)

            if len(immediate_replies) == 2 and len(server_sequences) == 1:
                break
        else:
            raise RuntimeError("timed out waiting for duplicate acknowledgements and first server request")

        first_reply_id = immediate_replies[0][0]["identification"]
        second_reply_id = immediate_replies[1][0]["identification"]
        if second_reply_id != ((first_reply_id + 1) & 0xFFFF):
            raise RuntimeError("duplicate peer request replies did not advance IPv4 ID monotonically")

        duplicate_quiet_deadline = time.monotonic() + 0.5
        while time.monotonic() < duplicate_quiet_deadline:
            try:
                packet, _ = receiver.recvfrom(65535)
            except socket.timeout:
                continue
            server_request = parse_server_request(packet)
            if server_request is not None:
                raise RuntimeError("duplicate peer request caused a second inner delivery")

        sender.sendto(request2, (OUTER_DESTINATION, 0))
        saw_second_reply = False
        saw_second_server_request = False
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not (saw_second_reply and saw_second_server_request):
            try:
                packet, _ = receiver.recvfrom(65535)
            except socket.timeout:
                continue

            if parse_immediate_reply(packet, request2_icmp) is not None:
                saw_second_reply = True
                continue

            server_request = parse_server_request(packet)
            if server_request is None:
                continue
            _, server_icmp, inner_icmp = server_request
            if inner_icmp["identifier"] != INNER_IDENTIFIER or inner_icmp["sequence"] != INNER_SEQUENCE + 1:
                raise RuntimeError("second server request carried the wrong inner Echo Reply")
            if inner_icmp["payload"] != second_payload:
                raise RuntimeError("second server request altered the inner Echo Reply payload")
            server_sequences.append(server_icmp["sequence"])
            send_acknowledgement(sender, server_icmp, 0x4202)
            saw_second_server_request = True

        if not saw_second_reply or not saw_second_server_request:
            raise RuntimeError("timed out waiting for the second Echo exchange")
        if server_sequences != [1, 2]:
            raise RuntimeError(f"server-originated request sequences were not ascending: {server_sequences}")

        print("RawSocket -> PingServer -> TunDevice multi-worker Echo v2 flow verified")
        return
    finally:
        sender.close()
        receiver.close()

    raise RuntimeError("PingServer Echo v2 flow did not complete")


if __name__ == "__main__":
    main()
