# Ping6 new IP ICMPv6 roundtrip

Exercises `TesterClient -> Ping6Client -> Ping6Server -> TesterServer` in both directions with four workers. The inner packet uses IPv4 Protocol 253 and both Ping6 nodes omit `send-replies`, selecting the default of no generated acknowledgements.

- CTest: `waterwall.ping6_new_ip_icmpv6_roundtrip`
- Prerequisites: production build and Linux user/network namespace support; no external network is used.
- Success: TesterClient reports completion on all worker lines before the deadline. Early exit, a missing marker, or an unexpected status fails.
- Run through `tests/run_test_lane.sh` with the registered lane, or inspect with `ctest --preset linux -N -V -R '^waterwall\.ping6_new_ip_icmpv6_roundtrip$'`.

The contract is one-time inner-packet delivery through real Ping6 client/server callbacks, including reverse-direction data as a fresh Echo Request.

The carrier reuses the actual IPv4 header and inserts Echo framing plus a final
saved-protocol byte, for nine bytes of overhead. A complete 1491-byte native
packet produces a 1500-byte carrier; 1492 bytes is refused. Both codec entry
points reject fragments, so real adapters explicitly reassemble before these
nodes. Address rewriting/restoration belongs to the chain; direct codec pairs
preserve their native tuple. These are fixture expectations, not MTU discovery.
