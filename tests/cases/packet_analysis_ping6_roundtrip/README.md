# Packet analysis Ping6 roundtrip

Generates six inner IPv4/ICMP packets through `PacketGenerator -> Ping6Client -> PacketCounter` with four workers. PacketCounter accepts only IPv4 Protocol 58 with the preserved source range `198.51.100.0/31` (three packets per source).

- CTest: `waterwall.packet_analysis_ping6_roundtrip`
- Expected report: six received, zero lost, all six classified under Protocol 58.
- Prerequisites: production build and the Linux integration harness; no external network is used.
- Inspect with `ctest --preset linux -N -V -R '^waterwall\.packet_analysis_ping6_roundtrip$'` and run through the registered lane wrapper.

This scenario verifies actual carrier output rather than merely checking codec constants.

The carrier reuses the actual IPv4 header and inserts Echo framing plus a final
saved-protocol byte, for nine bytes of overhead. A complete 1491-byte native
packet produces a 1500-byte carrier; 1492 bytes is refused. Both codec entry
points reject fragments, so real adapters explicitly reassemble before these
nodes. Address rewriting/restoration belongs to the chain; direct codec pairs
preserve their native tuple. These are fixture expectations, not MTU discovery.
