#!/usr/bin/env python3
"""Exercise RawSocket -> IpOverrider -> Ping6Server -> TunDevice with real Protocol 58 adapters.

The privileged namespace runner starts the adjacent multiworker configuration.
The probe independently constructs and verifies outer IPv4/ICMPv6 Echo packets
while retaining ordinary inner IPv4/ICMP packets. It checks exact payloads,
checksums, reply ordering, TOS/TTL and fragmentation policy, duplicate
acknowledgements without duplicate inner delivery, advancing reply IDs, and
server request sequences. Raw-socket and TUN privileges are required; the case
uses no external network and measures no speed.
CTest: waterwall.ping6_direct_real_adapters_roundtrip.
"""

import ipaddress
import socket
import struct
import time


TUN_NAME = "wwping6direct0"
PEER_IDENTIFIER = 4660
SERVER_IDENTIFIER = 4661
INNER_IDENTIFIER = 0x2A2A
INNER_SEQUENCE = 7
INNER_SOURCE = "10.252.30.2"
INNER_DESTINATION = "10.252.30.1"
OUTER_SOURCE = "127.0.0.2"
OUTER_DESTINATION = "127.0.0.1"
PSEUDO_SOURCE = "::"
PSEUDO_DESTINATION = "::"
PING6_PROTOCOL = 58
CARRIER_PROTOCOL = 58
IPV6_IN_IPV4 = False
NATIVE_MAX = 1491
PING6_ECHO_REQUEST = 128
PING6_ECHO_REPLY = 129
PAYLOAD = b"waterwall-ping6-direct-real-adapters"
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


def ping6_echo(icmp_type, identifier, sequence, payload, source, destination):
    frame = struct.pack("!BBHHH", icmp_type, 0, 0, identifier, sequence) + payload
    pseudo_header = (
        ipaddress.IPv6Address(source).packed
        + ipaddress.IPv6Address(destination).packed
        + struct.pack("!I3xB", len(frame), PING6_PROTOCOL)
    )
    return frame[:2] + struct.pack("!H", checksum(pseudo_header + frame)) + frame[4:]


def ping6_checksum(payload, source, destination):
    pseudo_header = (
        ipaddress.IPv6Address(source).packed
        + ipaddress.IPv6Address(destination).packed
        + struct.pack("!I3xB", len(payload), PING6_PROTOCOL)
    )
    return checksum(pseudo_header + payload)


def wrap_carrier_echo(frame, source, destination, traffic_class=0):
    if not IPV6_IN_IPV4:
        return frame
    header = struct.pack("!IHBB16s16s", (6 << 28) | (traffic_class << 20), len(frame), 58, 64,
                         ipaddress.IPv6Address(source).packed, ipaddress.IPv6Address(destination).packed)
    return header + frame


def parse_carrier_echo(payload, source, destination):
    if IPV6_IN_IPV4:
        if len(payload) < 48:
            raise RuntimeError("truncated nested IPv6/Echo carrier")
        version_class_flow, length, next_header, hop_limit, src, dst = struct.unpack("!IHBB16s16s", payload[:40])
        if version_class_flow >> 28 != 6 or length != len(payload) - 40 or next_header != 58:
            raise RuntimeError("invalid fixed IPv6 envelope geometry")
        if src != ipaddress.IPv6Address(source).packed or dst != ipaddress.IPv6Address(destination).packed:
            raise RuntimeError("nested IPv6 endpoint pair differs from mirrored settings")
        if (version_class_flow >> 20) & 255 != REQUEST_TOS or version_class_flow & 0xFFFFF or hop_limit != 64:
            raise RuntimeError("generated inner IPv6 Traffic Class/Flow Label/Hop Limit policy differs")
        # Use the addresses actually read from the carrier as independent checksum inputs.
        source, destination = str(ipaddress.IPv6Address(src)), str(ipaddress.IPv6Address(dst))
        payload = payload[40:]
    return parse_ping6(payload, source, destination)


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
    if not 20 <= header_len <= 60 or total_len != len(packet) or total_len < header_len:
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


def parse_ping6(payload, source, destination):
    if len(payload) < 8 or ping6_checksum(payload, source, destination) != 0:
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
    if outer["protocol"] != CARRIER_PROTOCOL:
        return None

    icmp = parse_carrier_echo(outer["payload"], PSEUDO_DESTINATION, PSEUDO_SOURCE)
    if icmp is None or icmp["type"] != PING6_ECHO_REPLY or icmp["code"] != 0:
        return None

    expected = parse_ping6(expected_request_icmp, PSEUDO_SOURCE, PSEUDO_DESTINATION)
    if expected is None:
        raise RuntimeError("test built an invalid ICMPv6 Echo Request")
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
    if outer["protocol"] != CARRIER_PROTOCOL:
        return None

    icmp = parse_carrier_echo(outer["payload"], PSEUDO_DESTINATION, PSEUDO_SOURCE)
    if icmp is None or icmp["type"] != PING6_ECHO_REQUEST or icmp["code"] != 0:
        return None
    if icmp["identifier"] != SERVER_IDENTIFIER:
        return None
    if outer["tos"] != REQUEST_TOS or outer["ttl"] != SERVER_TTL:
        raise RuntimeError("server-originated Echo Request has wrong TOS/TTL")
    if outer["flags_offset"] & 0x3FFF:
        raise RuntimeError("server data carrier is fragmented")
    # There is one IPv4 header. The exact native ICMP body is followed by its
    # original protocol number; address restoration is the chain's policy.
    if not icmp["payload"] or icmp["payload"][-1] != socket.IPPROTO_ICMP:
        raise RuntimeError("server carrier lacks its final native-protocol trailer")
    native_body = icmp["payload"][:-1]
    if len(packet) != 20 + (40 if IPV6_IN_IPV4 else 0) + 8 + len(native_body) + 1 or len(packet) > 1500:
        raise RuntimeError("server carrier has wrong mode-specific expansion")
    inner_icmp = parse_icmp(native_body)
    if inner_icmp is None or inner_icmp["type"] != 0 or inner_icmp["code"] != 0:
        raise RuntimeError("inner Echo Reply was not preserved")
    return outer, icmp, inner_icmp


def make_peer_request(outer_sequence, inner_sequence, payload, identification):
    inner_icmp = icmp_echo(8, INNER_IDENTIFIER, inner_sequence, payload)
    request_icmp = ping6_echo(
        PING6_ECHO_REQUEST,
        PEER_IDENTIFIER,
        outer_sequence,
        inner_icmp + bytes([socket.IPPROTO_ICMP]),
        PSEUDO_SOURCE,
        PSEUDO_DESTINATION,
    )
    request = ipv4_packet(
        OUTER_SOURCE,
        OUTER_DESTINATION,
        CARRIER_PROTOCOL,
        wrap_carrier_echo(request_icmp, PSEUDO_SOURCE, PSEUDO_DESTINATION, REQUEST_TOS),
        identification,
        tos=REQUEST_TOS,
    )
    return request_icmp, request


def send_acknowledgement(sender, server_icmp, identification):
    acknowledgement_icmp = ping6_echo(
        PING6_ECHO_REPLY,
        server_icmp["identifier"],
        server_icmp["sequence"],
        server_icmp["payload"],
        PSEUDO_SOURCE,
        PSEUDO_DESTINATION,
    )
    acknowledgement = ipv4_packet(
        OUTER_SOURCE,
        OUTER_DESTINATION,
        CARRIER_PROTOCOL,
        wrap_carrier_echo(acknowledgement_icmp, PSEUDO_SOURCE, PSEUDO_DESTINATION),
        identification,
    )
    sender.sendto(acknowledgement, (OUTER_DESTINATION, 0))


def main():
    wait_for_tun()

    request1_icmp, request1 = make_peer_request(1, INNER_SEQUENCE, PAYLOAD, 0x4101)
    second_payload = PAYLOAD + b"-second"
    request2_icmp, request2 = make_peer_request(2, INNER_SEQUENCE + 1, second_payload, 0x4102)

    receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, CARRIER_PROTOCOL)
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

        # Native size includes IPv4 (20) and native ICMP (8), then the
        # selected 9/49 carrier bytes. Loopback has ample path MTU; the codec ceiling is fixed.
        maximum_payload = bytes((i & 0xFF) for i in range(NATIVE_MAX - 20 - 8))
        maximum_icmp, maximum_packet = make_peer_request(3, INNER_SEQUENCE + 2, maximum_payload, 0x4103)
        if len(maximum_packet) != 1500:
            raise RuntimeError("maximum fixture does not have mode-specific expansion")
        sender.sendto(maximum_packet, (OUTER_DESTINATION, 0))
        saw_max_reply = saw_max_data = False
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not (saw_max_reply and saw_max_data):
            try:
                packet, _ = receiver.recvfrom(65535)
            except socket.timeout:
                continue
            if parse_immediate_reply(packet, maximum_icmp) is not None:
                saw_max_reply = True
                continue
            result = parse_server_request(packet)
            if result is not None:
                _, carrier_icmp, native_icmp = result
                if native_icmp["sequence"] != INNER_SEQUENCE + 2 or native_icmp["payload"] != maximum_payload:
                    raise RuntimeError("maximum native packet was changed")
                if carrier_icmp["sequence"] != 3 or len(packet) != 1500:
                    raise RuntimeError("maximum data carrier sequence or size is wrong")
                send_acknowledgement(sender, carrier_icmp, 0x4203)
                saw_max_data = True
        if not (saw_max_reply and saw_max_data):
            raise RuntimeError(f"{NATIVE_MAX}-byte native packet did not complete")
        oversized_icmp, oversized_packet = make_peer_request(4, INNER_SEQUENCE + 3, maximum_payload + b"x", 0x4104)
        if len(oversized_packet) != 1501:
            raise RuntimeError("oversized fixture has wrong geometry")
        sender.sendto(oversized_packet, (OUTER_DESTINATION, 0))
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            try:
                packet, _ = receiver.recvfrom(65535)
            except socket.timeout:
                continue
            if parse_immediate_reply(packet, oversized_icmp) is not None or parse_server_request(packet) is not None:
                raise RuntimeError(f"{NATIVE_MAX + 1}-byte native packet escaped the codec size ceiling")

        print(f"RawSocket -> IpOverrider -> Ping6Server -> TunDevice multi-worker Protocol {CARRIER_PROTOCOL} flow verified")
        return
    finally:
        sender.close()
        receiver.close()

    raise RuntimeError("Ping6Server Protocol 58 flow did not complete")


if __name__ == "__main__":
    main()
