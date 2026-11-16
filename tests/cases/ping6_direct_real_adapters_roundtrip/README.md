# Ping6 direct real adapters roundtrip

Runs the privileged `RawSocket -> Ping6Server -> TunDevice` topology on four workers. RawSocket captures only IPv4 Protocol 58 from `127.0.0.2` and uses `opaque-flow-mode: auto`.

- CTest: `waterwall.ping6_direct_real_adapters_roundtrip`
- Prerequisites: Linux network namespaces, root/CAP_NET_ADMIN, raw sockets, TUN, and the tools used by `probe.py`; missing prerequisites must remain visible skips, not passes.
- Network use: loopback inside the private namespace only.
- Probe assertions: independent ICMPv6 pseudo-header checksums, type 128 data requests, type 129 acknowledgements, exact inner IPv4/ICMP payloads, duplicate suppression, advancing reply IDs, TOS/TTL, DF policy, and server request sequences.

Inspect with `ctest --preset linux -N -V -R '^waterwall\.ping6_direct_real_adapters_roundtrip$'` and execute through the registered lane wrapper. The probe is the end-to-end adapter check; component tests alone do not replace it.
