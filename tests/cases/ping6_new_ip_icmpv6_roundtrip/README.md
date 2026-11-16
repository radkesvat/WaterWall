# Ping6 new IP ICMPv6 roundtrip

Exercises `TesterClient -> Ping6Client -> Ping6Server -> TesterServer` in both directions with four workers. The inner packet uses IPv4 Protocol 253 and both Ping6 nodes omit `send-replies`, selecting the default of no generated acknowledgements.

- CTest: `waterwall.ping6_new_ip_icmpv6_roundtrip`
- Prerequisites: production build and Linux user/network namespace support; no external network is used.
- Success: TesterClient reports completion on all worker lines before the deadline. Early exit, a missing marker, or an unexpected status fails.
- Run through `tests/run_test_lane.sh` with the registered lane, or inspect with `ctest --preset linux -N -V -R '^waterwall\.ping6_new_ip_icmpv6_roundtrip$'`.

The contract is one-time inner-packet delivery through real Ping6 client/server callbacks, including reverse-direction data as a fresh Echo Request.
