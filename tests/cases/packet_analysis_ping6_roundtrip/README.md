# Packet analysis Ping6 roundtrip

Generates six inner IPv4/ICMP packets through `PacketGenerator -> Ping6Client -> PacketCounter` with four workers. PacketCounter accepts only outer IPv4 Protocol 58 from `192.0.2.30`.

- CTest: `waterwall.packet_analysis_ping6_roundtrip`
- Expected report: six received, zero lost, all six classified under Protocol 58.
- Prerequisites: production build and the Linux integration harness; no external network is used.
- Inspect with `ctest --preset linux -N -V -R '^waterwall\.packet_analysis_ping6_roundtrip$'` and run through the registered lane wrapper.

This scenario verifies actual carrier output rather than merely checking codec constants.
