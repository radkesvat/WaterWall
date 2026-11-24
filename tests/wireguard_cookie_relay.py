#!/usr/bin/env python3
"""Relay and verify the WireGuard overload-cookie integration exchange.

The owner, tests/run_wireguard_cookie_case.sh, starts this loopback UDP relay,
runs WaterWall with forced system load, then invokes --verify on its JSONL trace.
Verification requires ordered cookie exchanges, fresh protected handshakes,
and subsequent data in both directions using their new indices.
The endpoint probe requires a new cookie after moving that initiation to another
source port, then verifies authenticated data roaming with replies on both ports.
This helper checks the recorded packet sequence; the owner supplies the runtime
case verdict, and this is not an independent cryptographic or throughput test.
CTest: waterwall.wireguard_cookie_overload_roundtrip and wireguard_cookie_source_port_1/_4.
"""

import argparse
import json
import select
import signal
import socket
import sys
from pathlib import Path


ZERO_MAC = "00" * 16


def describe_packet(packet: bytes, source_port: int) -> dict:
    # Match the engine's wireguardGetMessageType() shape checks. This labels
    # datagrams for the trace; it does not establish cryptographic validity.
    length = len(packet)
    message_type = 0
    if length >= 4 and packet[1:4] == b"\0\0\0":
        candidate = packet[0]
        if ((candidate == 1 and length == 148)
                or (candidate == 2 and length == 92)
                or (candidate == 3 and length == 64)
                or (candidate == 4 and length >= 32)):
            message_type = candidate
    event = {
        "source_port": source_port,
        "type": message_type,
        "raw": packet.hex(),
    }

    if message_type in (1, 2):
        event["sender"] = int.from_bytes(packet[4:8], "little")
        event["receiver"] = int.from_bytes(packet[8:12], "little") if event["type"] == 2 else 0
        event["mac1"] = packet[-32:-16].hex()
        event["mac2"] = packet[-16:].hex()
    elif message_type == 3:
        event["receiver"] = int.from_bytes(packet[4:8], "little")
    elif message_type == 4:
        event["receiver"] = int.from_bytes(packet[4:8], "little")

    return event


def run_relay(args: argparse.Namespace) -> int:
    running = True
    client_endpoint = None
    moved_probe = False
    moved_challenge = False
    moved_retry = False
    moved_delivery = False
    roaming_started = False
    held_replies = []
    ready_to_roam = False

    def stop(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay.bind(("127.0.0.1", args.listen_port))
    alternate = None
    if args.endpoint_probe:
        alternate = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        alternate.bind(("127.0.0.1", args.listen_port + 1))
    server_route = relay
    Path(args.ready_file).touch()

    with open(args.trace_file, "w", encoding="utf-8", buffering=1) as trace:
        while running:
            readable, _, _ = select.select([relay] + ([alternate] if alternate else []), [], [], 0.2)
            if not readable:
                continue
            incoming = readable[0]
            packet, source = incoming.recvfrom(65535)

            if source[1] != args.server_port:
                if client_endpoint is None:
                    client_endpoint = source
                if source != client_endpoint:
                    continue
            source_port = args.server_port if source[1] == args.server_port else args.client_port
            if source_port == args.client_port:
                destination_port = args.server_port
            elif source_port == args.server_port:
                destination_port = args.client_port
            else:
                continue

            event = describe_packet(packet, source_port)
            event["relay_port"] = incoming.getsockname()[1]
            if args.endpoint_probe and source_port == args.server_port:
                if incoming is alternate and event["type"] == 3 and moved_probe and not moved_challenge:
                    moved_challenge = True
                    event["endpoint_step"] = "moved_challenge"
                elif incoming is alternate and event["type"] == 4:
                    moved_delivery = True
                    event["endpoint_step"] = "moved_delivery"
                    if len(packet) == 32 and held_replies:
                        ready_to_roam = True
                elif incoming is relay and event["type"] == 4 and roaming_started:
                    event["endpoint_step"] = "roaming_delivery"
            if args.endpoint_probe and source_port == args.client_port:
                if event["type"] == 1 and event["mac2"] != ZERO_MAC:
                    if not moved_probe:
                        moved_probe = True
                        event["endpoint_step"] = "moved_probe"
                    elif moved_challenge and not moved_retry:
                        moved_retry = True
                        event["endpoint_step"] = "moved_retry"
                    server_route = alternate
                # A new authenticated packet from the original source port must
                # move the peer back after data was delivered through the new one.
                if event["type"] == 4 and moved_delivery and ready_to_roam and not roaming_started:
                    roaming_started = True
                    server_route = relay
                    event["endpoint_step"] = "authenticated_roam"

            trace.write(json.dumps(event, sort_keys=True) + "\n")

            if destination_port == args.client_port:
                if (args.endpoint_probe and incoming is alternate and event["type"] == 4
                        and (len(packet) > 32 or held_replies)):
                    # Preserve application order while keeping the runtime alive
                    # until fresh keepalives prove the reverse roam. A later
                    # keepalive on this same socket follows these queued replies.
                    # Retain keepalives too: delivering their larger nonce first
                    # could put older held replies outside the replay window.
                    held_replies.append(packet)
                    continue
                # Keep the client's pinned transport endpoint unchanged while
                # presenting two real source endpoints to the server.
                if args.endpoint_probe and incoming is relay and event["type"] == 4 and roaming_started:
                    for held in held_replies:
                        relay.sendto(held, client_endpoint)
                    held_replies.clear()
                relay.sendto(packet, client_endpoint)
            else:
                server_route.sendto(packet, ("127.0.0.1", destination_port))

    relay.close()
    if alternate:
        alternate.close()
    return 0


def next_matching(events: list[dict], start: int, predicate):
    for index in range(start, len(events)):
        if predicate(events[index]):
            return index, events[index]
    return None, None


def verify_trace(args: argparse.Namespace) -> int:
    with open(args.trace_file, "r", encoding="utf-8") as trace:
        events = [json.loads(line) for line in trace if line.strip()]

    if args.endpoint_probe:
        steps = [event.get("endpoint_step") for event in events]
        expected = ["moved_probe", "moved_challenge", "moved_retry", "moved_delivery",
                    "authenticated_roam", "roaming_delivery"]
        position = 0
        for step in steps:
            if position < len(expected) and step == expected[position]:
                position += 1
        assert position == len(expected), f"source-port cookie/roaming sequence incomplete: {steps}"
        probe = next(event for event in events if event.get("endpoint_step") == "moved_probe")
        challenge = next(event for event in events if event.get("endpoint_step") == "moved_challenge")
        retry = next(event for event in events if event.get("endpoint_step") == "moved_retry")
        assert challenge["receiver"] == probe["sender"], "port challenge did not match the moved initiation"
        assert probe["sender"] != retry["sender"] and probe["mac1"] != retry["mac1"], (
            "retry after the port challenge did not build a fresh initiation"
        )

    for start, initiation in enumerate(events):
        if not (
            initiation.get("source_port") == args.client_port
            and initiation.get("type") == 1
            and initiation.get("mac2") == ZERO_MAC
        ):
            continue

        cookie1_pos, _ = next_matching(
            events,
            start + 1,
            lambda event: event.get("source_port") == args.server_port
            and event.get("type") == 3
            and event.get("receiver") == initiation["sender"],
        )
        if cookie1_pos is None:
            continue

        response_pos, response = next_matching(
            events,
            cookie1_pos + 1,
            lambda event: event.get("source_port") == args.server_port
            and event.get("type") == 2
            and event.get("mac2") == ZERO_MAC,
        )
        if response_pos is None:
            continue

        if not any(
            event.get("source_port") == args.client_port
            and event.get("type") == 1
            and event.get("sender") == response["receiver"]
            and event.get("sender") != initiation["sender"]
            and event.get("mac1") != initiation["mac1"]
            and event.get("mac2") != ZERO_MAC
            for event in events[cookie1_pos + 1:response_pos]
        ):
            continue

        cookie2_pos, _ = next_matching(
            events,
            response_pos + 1,
            lambda event: event.get("source_port") == args.client_port
            and event.get("type") == 3
            and event.get("receiver") == response["sender"],
        )
        if cookie2_pos is None:
            continue

        retry_pos, retry = next_matching(
            events,
            cookie2_pos + 1,
            lambda event: event.get("source_port") == args.client_port
            and event.get("type") == 1
            and event.get("sender") != response["receiver"]
            and event.get("mac2") != ZERO_MAC,
        )
        if retry_pos is None:
            continue

        response2_pos, response2 = next_matching(
            events,
            retry_pos + 1,
            lambda event: event.get("source_port") == args.server_port
            and event.get("type") == 2
            and event.get("receiver") == retry["sender"]
            and event.get("sender") != response["sender"]
            and event.get("mac1") != response["mac1"]
            and event.get("mac2") != ZERO_MAC,
        )
        if response2_pos is None:
            continue

        client_data_pos, _ = next_matching(
            events,
            response2_pos + 1,
            lambda event: event.get("source_port") == args.client_port
            and event.get("type") == 4
            and event.get("receiver") == response2["sender"],
        )
        if client_data_pos is None:
            continue

        server_data_pos, _ = next_matching(
            events,
            client_data_pos + 1,
            lambda event: event.get("source_port") == args.server_port
            and event.get("type") == 4
            and event.get("receiver") == retry["sender"],
        )
        if server_data_pos is not None:
            print("WireGuard overload cookie sequence verified with fresh initiations and responses")
            return 0

    print("WireGuard overload cookie sequence was not observed", file=sys.stderr)
    for event in events:
        print(json.dumps(event, sort_keys=True), file=sys.stderr)
    return 1


def verify_junk(args):
    events = [json.loads(line) for line in Path(args.trace_file).read_text().splitlines()]
    outbound = [event for event in events if event["source_port"] == args.client_port]
    assert sum(event["type"] == 0 for event in outbound) >= 3, "outbound junk was not observed"
    assert any(event["type"] == 1 and len(bytes.fromhex(event["raw"])) == 148 for event in outbound)
    for port in (args.client_port, args.server_port):
        assert any(event["source_port"] == port and event["type"] == 4 for event in events), "missing bidirectional data"
    print("Outbound junk and intact bidirectional WireGuard datagrams verified")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace-file", required=True)
    parser.add_argument("--client-port", type=int, default=26950)
    parser.add_argument("--server-port", type=int, default=26951)
    parser.add_argument("--listen-port", type=int, default=26960)
    parser.add_argument("--ready-file")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--junk", action="store_true")
    parser.add_argument("--endpoint-probe", action="store_true")
    args = parser.parse_args()
    if not args.verify and not args.ready_file:
        parser.error("--ready-file is required in relay mode")
    return args


if __name__ == "__main__":
    arguments = parse_args()
    raise SystemExit((verify_junk(arguments) if arguments.junk else verify_trace(arguments))
                     if arguments.verify else run_relay(arguments))
