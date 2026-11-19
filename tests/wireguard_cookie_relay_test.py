#!/usr/bin/env python3
"""Datagram classification and junk trace verdicts, without sockets or randomness.

Includes a QUIC long-header prefix that previously looked like WireGuard type 193.
CTest: waterwall.wireguard_cookie_relay.
"""

import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from wireguard_cookie_relay import describe_packet, verify_junk


CLIENT_PORT = 26750
SERVER_PORT = 26751
QUIC_DATAGRAM = bytes.fromhex("c1 00 00 00 01") + bytes(1195)


def datagram(message_type, length):
    return (bytes((message_type, 0, 0, 0)) + bytes(max(0, length - 4)))[:length]


class WireGuardCookieRelayTest(unittest.TestCase):
    def test_valid_message_shapes(self):
        for message_type, lengths in ((1, (148,)), (2, (92,)), (3, (64,)), (4, (32, 33, 148))):
            for length in lengths:
                with self.subTest(message_type=message_type, length=length):
                    packet = datagram(message_type, length)
                    event = describe_packet(packet, CLIENT_PORT)
                    self.assertEqual(event["type"], message_type)
                    self.assertEqual(event["raw"], packet.hex())
                    self.assertEqual(event["source_port"], CLIENT_PORT)
                    if message_type in (1, 2):
                        self.assertIn("sender", event)
                        self.assertIn("mac1", event)
                        self.assertIn("mac2", event)
                    self.assertIn("receiver", event)

    def test_other_datagrams_are_junk(self):
        packets = [QUIC_DATAGRAM]
        packets.extend(datagram(1, length) for length in range(4))
        for message_type, length in ((1, 148), (2, 92), (3, 64)):
            packets.extend(datagram(message_type, invalid) for invalid in (length - 1, length + 1))
        packets.extend((datagram(1, 92), datagram(2, 148), datagram(4, 31)))
        packets.extend(datagram(message_type, 148) for message_type in (0, 5, 193, 255))
        for message_type, length in ((1, 148), (2, 92), (3, 64), (4, 32)):
            for reserved in range(1, 4):
                packet = bytearray(datagram(message_type, length))
                packet[reserved] = 1
                packets.append(bytes(packet))
        for packet in packets:
            with self.subTest(prefix=packet[:5].hex(), length=len(packet)):
                self.assertEqual(describe_packet(packet, CLIENT_PORT), {
                    "source_port": CLIENT_PORT, "type": 0, "raw": packet.hex(),
                })

    def test_junk_verdict_with_quic_prefix_and_required_traffic(self):
        junk = (QUIC_DATAGRAM, b"\x16\x03\x03\x00\x01", b"\x00\x01\x02\x03")
        events = [describe_packet(packet, CLIENT_PORT) for packet in junk]
        events.extend((describe_packet(datagram(1, 148), CLIENT_PORT),
                       describe_packet(datagram(4, 48), CLIENT_PORT),
                       describe_packet(datagram(4, 48), SERVER_PORT)))
        with tempfile.TemporaryDirectory(prefix="waterwall-junk-relay-") as directory:
            trace = Path(directory) / "trace.jsonl"
            args = argparse.Namespace(trace_file=trace, client_port=CLIENT_PORT, server_port=SERVER_PORT)

            def verify(selected):
                trace.write_text("".join(json.dumps(event) + "\n" for event in selected), encoding="utf-8")
                with contextlib.redirect_stdout(io.StringIO()):
                    return verify_junk(args)

            self.assertEqual(verify(events), 0)
            with self.assertRaisesRegex(AssertionError, "outbound junk was not observed"):
                verify(events[1:])
            for port in (CLIENT_PORT, SERVER_PORT):
                with self.subTest(missing_data_direction=port):
                    with self.assertRaisesRegex(AssertionError, "missing bidirectional data"):
                        verify([event for event in events
                                if not (event["type"] == 4 and event["source_port"] == port)])


if __name__ == "__main__":
    unittest.main()
