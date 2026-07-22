#!/usr/bin/env python3

import argparse
import json
import signal
import socket
import sys
from pathlib import Path


ZERO_MAC = "00" * 16


def describe_packet(packet: bytes, source_port: int) -> dict:
    event = {
        "source_port": source_port,
        "type": packet[0] if len(packet) >= 4 and packet[1:4] == b"\0\0\0" else 0,
        "raw": packet.hex(),
    }

    if event["type"] in (1, 2) and len(packet) in (148, 92):
        event["sender"] = int.from_bytes(packet[4:8], "little")
        event["receiver"] = int.from_bytes(packet[8:12], "little") if event["type"] == 2 else 0
        event["mac1"] = packet[-32:-16].hex()
        event["mac2"] = packet[-16:].hex()
    elif event["type"] == 3 and len(packet) == 64:
        event["receiver"] = int.from_bytes(packet[4:8], "little")
    elif event["type"] == 4 and len(packet) >= 32:
        event["receiver"] = int.from_bytes(packet[4:8], "little")

    return event


def run_relay(args: argparse.Namespace) -> int:
    running = True
    initiation_cookie = None
    response_cookie = None
    initiation_cookie_replayed = False
    response_cookie_replayed = False

    def stop(_signum, _frame):
        nonlocal running
        running = False

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    relay = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    relay.bind(("127.0.0.1", args.listen_port))
    relay.settimeout(0.2)
    Path(args.ready_file).touch()

    with open(args.trace_file, "w", encoding="utf-8", buffering=1) as trace:
        while running:
            try:
                packet, source = relay.recvfrom(65535)
            except socket.timeout:
                continue

            source_port = source[1]
            if source_port == args.client_port:
                destination_port = args.server_port
            elif source_port == args.server_port:
                destination_port = args.client_port
            else:
                continue

            event = describe_packet(packet, source_port)
            trace.write(json.dumps(event, sort_keys=True) + "\n")

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
                relay.sendto(initiation_cookie, ("127.0.0.1", args.client_port))
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
                relay.sendto(response_cookie, ("127.0.0.1", args.server_port))
                response_cookie_replayed = True
                continue

            relay.sendto(packet, ("127.0.0.1", destination_port))

    relay.close()
    return 0


def next_matching(events: list[dict], start: int, predicate):
    for index in range(start, len(events)):
        if predicate(events[index]):
            return index, events[index]
    return None, None


def verify_trace(args: argparse.Namespace) -> int:
    with open(args.trace_file, "r", encoding="utf-8") as trace:
        events = [json.loads(line) for line in trace if line.strip()]

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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trace-file", required=True)
    parser.add_argument("--client-port", type=int, default=26950)
    parser.add_argument("--server-port", type=int, default=26951)
    parser.add_argument("--listen-port", type=int, default=26960)
    parser.add_argument("--ready-file")
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if not args.verify and not args.ready_file:
        parser.error("--ready-file is required in relay mode")
    return args


if __name__ == "__main__":
    arguments = parse_args()
    raise SystemExit(verify_trace(arguments) if arguments.verify else run_relay(arguments))
