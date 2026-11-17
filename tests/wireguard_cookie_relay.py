#!/usr/bin/env python3
"""Relay and verify the WireGuard overload-cookie integration exchange.

The owner, tests/run_wireguard_cookie_case.sh, starts this loopback UDP relay,
runs WaterWall with forced system load, then invokes --verify on its JSONL trace.
The relay drops each side's first cookie-protected retry and repeats its valid
cookie. Verification requires ordered cookie exchanges, preserved handshake
indices/MAC1/body, exact repeated retries, and subsequent data in both directions.
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
    initiation_cookie = None
    response_cookie = None
    initiation_cookie_replayed = False
    response_cookie_replayed = False
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
            trace.write(json.dumps(event, sort_keys=True) + "\n")

            if args.junk:
                relay.sendto(packet, client_endpoint if source_port == args.server_port else ("127.0.0.1", args.server_port))
                continue

            if source_port == args.server_port and event.get("type") == 3:
                initiation_cookie = packet
            elif source_port == args.client_port and event.get("type") == 3:
                response_cookie = packet

            # Make each side process the same valid cookie twice before its
            # handshake completes. The first cookie-protected retry was
            # successfully forwarded to this relay but is deliberately dropped;
            # retaining pending state is what permits the second retry.
            if (
                source_port == args.client_port
                and event.get("type") == 1
                and event.get("mac2") != ZERO_MAC
                and initiation_cookie is not None
                and not initiation_cookie_replayed
            ):
                replay = describe_packet(initiation_cookie, args.server_port)
                replay["injected"] = True
                trace.write(json.dumps(replay, sort_keys=True) + "\n")
                relay.sendto(initiation_cookie, client_endpoint)
                initiation_cookie_replayed = True
                continue

            if (
                source_port == args.server_port
                and event.get("type") == 2
                and event.get("mac2") != ZERO_MAC
                and response_cookie is not None
                and not response_cookie_replayed
            ):
                replay = describe_packet(response_cookie, args.client_port)
                replay["injected"] = True
                trace.write(json.dumps(replay, sort_keys=True) + "\n")
                server_route.sendto(response_cookie, ("127.0.0.1", args.server_port))
                response_cookie_replayed = True
                continue

            if args.endpoint_probe and source_port == args.client_port:
                if event["type"] == 1 and event.get("mac2") != ZERO_MAC and initiation_cookie_replayed:
                    if not moved_probe:
                        moved_probe = True
                        step = "moved_probe"
                    elif moved_challenge and not moved_retry:
                        moved_retry = True
                        step = "moved_retry"
                    else:
                        step = None
                    server_route = alternate
                    if step:
                        trace.write(json.dumps({"endpoint_step": step, "raw": packet.hex()}, sort_keys=True) + "\n")
                # A new authenticated packet from the original source port must
                # move the peer back after data was delivered through the new one.
                if event["type"] == 4 and moved_delivery and ready_to_roam and not roaming_started:
                    roaming_started = True
                    server_route = relay
                    trace.write(json.dumps({"endpoint_step": "authenticated_roam", "raw": packet.hex()}, sort_keys=True) + "\n")

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
        retry = next(event for event in events if event.get("endpoint_step") == "moved_retry")
        assert probe["raw"][:-32] == retry["raw"][:-32], "port challenge replaced pending initiation"
        assert probe["raw"][-32:] != retry["raw"][-32:], "new source port reused the old cookie MAC"

    for start, initiation in enumerate(events):
        if not (
            initiation.get("source_port") == args.client_port
            and initiation.get("type") == 1
            and initiation.get("mac2") == ZERO_MAC
        ):
            continue

        initiator_index = initiation["sender"]
        cookie1_pos, _ = next_matching(
            events,
            start + 1,
            lambda event: event.get("source_port") == args.server_port
            and event.get("type") == 3
            and event.get("receiver") == initiator_index,
        )
        if cookie1_pos is None:
            continue

        retry1_pos, retry_initiation = next_matching(
            events,
            cookie1_pos + 1,
            lambda event: event.get("source_port") == args.client_port
            and event.get("type") == 1
            and event.get("sender") == initiator_index
            and event.get("mac1") == initiation.get("mac1")
            and event.get("mac2") != ZERO_MAC
            and bytes.fromhex(event["raw"][:-32]) == bytes.fromhex(initiation["raw"][:-32]),
        )
        if retry1_pos is None:
            continue

        cookie1_repeat_pos, _ = next_matching(
            events,
            retry1_pos + 1,
            lambda event: event.get("injected") is True
            and event.get("source_port") == args.server_port
            and event.get("type") == 3
            and event.get("receiver") == initiator_index,
        )
        if cookie1_repeat_pos is None:
            continue

        retry1_repeat_pos, _ = next_matching(
            events,
            cookie1_repeat_pos + 1,
            lambda event: event.get("source_port") == args.client_port
            and event.get("type") == 1
            and event.get("sender") == initiator_index
            and event.get("raw") == retry_initiation.get("raw"),
        )
        if retry1_repeat_pos is None:
            continue

        response_pos, response = next_matching(
            events,
            retry1_repeat_pos + 1,
            lambda event: event.get("source_port") == args.server_port
            and event.get("type") == 2
            and event.get("receiver") == initiator_index
            and event.get("mac2") == ZERO_MAC,
        )
        if response_pos is None:
            continue

        responder_index = response["sender"]
        cookie2_pos, _ = next_matching(
            events,
            response_pos + 1,
            lambda event: event.get("source_port") == args.client_port
            and event.get("type") == 3
            and event.get("receiver") == responder_index,
        )
        if cookie2_pos is None:
            continue

        retry2_pos, retry_response = next_matching(
            events,
            cookie2_pos + 1,
            lambda event: event.get("source_port") == args.server_port
            and event.get("type") == 2
            and event.get("sender") == responder_index
            and event.get("receiver") == initiator_index
            and event.get("mac1") == response.get("mac1")
            and event.get("mac2") != ZERO_MAC
            and bytes.fromhex(event["raw"][:-32]) == bytes.fromhex(response["raw"][:-32]),
        )
        if retry2_pos is None:
            continue

        cookie2_repeat_pos, _ = next_matching(
            events,
            retry2_pos + 1,
            lambda event: event.get("injected") is True
            and event.get("source_port") == args.client_port
            and event.get("type") == 3
            and event.get("receiver") == responder_index,
        )
        if cookie2_repeat_pos is None:
            continue

        retry2_repeat_pos, _ = next_matching(
            events,
            cookie2_repeat_pos + 1,
            lambda event: event.get("source_port") == args.server_port
            and event.get("type") == 2
            and event.get("sender") == responder_index
            and event.get("raw") == retry_response.get("raw"),
        )
        if retry2_repeat_pos is None:
            continue

        client_data_pos, _ = next_matching(
            events,
            retry2_repeat_pos + 1,
            lambda event: event.get("source_port") == args.client_port
            and event.get("type") == 4
            and event.get("receiver") == responder_index,
        )
        if client_data_pos is None:
            continue

        server_data_pos, _ = next_matching(
            events,
            client_data_pos + 1,
            lambda event: event.get("source_port") == args.server_port
            and event.get("type") == 4
            and event.get("receiver") == initiator_index,
        )
        if server_data_pos is not None:
            print(
                "WireGuard overload cookie sequence verified, including repeated exact initiation and response retries"
            )
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
