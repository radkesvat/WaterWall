# Ping6 direct real adapters roundtrip

Runs the privileged `RawSocket -> IpOverrider -> Ping6Server -> TunDevice` topology on four workers. RawSocket captures only IPv4 Protocol 58 from `127.0.0.2` and uses `opaque-flow-mode: peer`.

- CTest: `waterwall.ping6_direct_real_adapters_roundtrip`
- Prerequisites: Linux network namespaces, root/CAP_NET_ADMIN, raw sockets, TUN, and the tools used by `probe.py`; missing prerequisites must remain visible skips, not passes.
- Network use: loopback inside the private namespace only.
- Probe assertions: independent ICMPv6 pseudo-header checksums, type 128 data requests, type 129 acknowledgements, exact native ICMP bodies and final protocol trailers, duplicate suppression, advancing reply IDs, TOS/TTL, DF policy, and server request sequences.

Inspect with `ctest --preset linux -N -V -R '^waterwall\.ping6_direct_real_adapters_roundtrip$'` and execute through the registered lane wrapper. The probe is the end-to-end adapter check; component tests alone do not replace it.

The carrier reuses the actual IPv4 header and inserts Echo framing plus a final
saved-protocol byte, for nine bytes of overhead. A complete 1491-byte native
packet produces a 1500-byte carrier; 1492 bytes is refused. Both codec entry
points reject fragments, so real adapters explicitly reassemble before these
nodes. Address rewriting/restoration belongs to the chain; direct codec pairs
preserve their native tuple. These are fixture expectations, not MTU discovery.

The real-adapter probe checks the 1491/1492-byte native boundary, generated
reply TTL 64/copied TOS, exact Echo body plus trailer, duplicate suppression and
independent data requests. IpOverrider restores the point-to-point TUN addresses
on receive and rewrites loopback carrier addresses on send. RawSocket uses
explicit peer grouping because the decoder is no longer directly adjacent.
