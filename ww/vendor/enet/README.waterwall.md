# ENet in WaterWall

Upstream: https://github.com/lsalzman/enet
Pinned commit: `5a9c537fd464b3c6d3c55e1d3bd47588faf71b42` (2026-06-23), version 1.3.18.
License: MIT; see `LICENSE`.

This directory contains the upstream files WaterWall uses, with the local patches
described below:

- `callbacks.c`, `compress.c`, `host.c`, `list.c`, `packet.c`, `peer.c`, `protocol.c`
- `unix.c`, `win32.c`
- `include/enet/*.h`
- `LICENSE`

Local changes:

`peer.c` initializes newly allocated fragment-reassembly storage
when no initial data is supplied. This covers reliable and unreliable fragments
and prevents unwritten gaps from exposing uninitialized memory; it does not add
fragment-coverage validation. The patch matches
[`2a2312f` in radkesvat/enet](https://github.com/radkesvat/enet/commit/2a2312fa92c437abfb626140434230f19a6b490a).

`peer.c` also charges each queued incoming command for its packet structure,
command structure, payload and fragment bitmap in `totalWaitingData`. Empty
messages therefore consume the receive budget. Delivery and discard release
the same charge. Fragment counts and size additions are checked before allocation.
The comments in `include/enet/enet.h` document the updated counter semantics.
The existing admission rule is preserved: a packet admitted below
`maximumWaitingData` may cross that threshold once. This counts requested queue
allocation sizes, excluding allocator overhead and packets already handed to
the application; it is not a limit on all ENet or process memory. WaterWall's
existing temporary threshold increase for a missing reliable command remains in
the driver. See `radkesvat_changes.txt` for the local change record.

`peer.c`, `protocol.c` and `include/enet/enet.h` bound peer timeout and ping
settings to 12 hours, preserving zero-as-default and the retry multiplier.
Initial and doubled retry durations saturate safely at that limit; retry counts
cannot wrap or produce an oversized shift. Maximum timeouts are checked on
protocol service passes independently of retry expiration, once per peer per
send-function invocation. Later datagram-building passes use the same cached
time and do not repeat queue reconstruction. A bit in the existing
peer flags distinguishes an active timeout origin from a valid timestamp of
zero. Queue reset clears it; acknowledgements and successful reliable-command
removal, including the CONNECT handshake, invalidate it so the origin is rebuilt
from remaining sent commands and queued retransmissions. Each outgoing reliable
command retains its first transmission time for the maximum deadline and its
most recent transmission time for the next retry. Regular servicing is
still required; the 12-hour cap leaves half the time-comparison window for delay.
WaterWall rejects timeout/ping settings above this cap and services active
protocol work every 10 ms, subject to event-loop delay.

`host.c` computes host and peer bandwidth allowances and packet throttle ratios
with 64-bit arithmetic. Each peer accumulates queued outgoing bytes in a 64-bit
counter for the sampling interval. Bandwidth settings on the wire use ENet's
32-bit fields.

`tests/enet_vendor_source_policy_test.py` holds the SHA-256 of every vendored file,
including these local patches, and fails when one differs or when another C source
or header appears here. No download occurs during builds. The local
`.clang-format` disables formatting to preserve the vendored source layout.

`tunnels/Internals/EnetCommon/CMakeLists.txt` compiles the protocol core
(`callbacks.c`, `host.c`, `list.c`, `packet.c`, `peer.c`, `protocol.c`) into the
`enet_protocol` object library. `compress.c` is not built: WaterWall does not use
ENet's range coder. `unix.c` and `win32.c` are never built into production
targets. `tunnels/Internals/EnetCommon/src/platform.c` provides ENet's platform
functions (`enet_socket_*`, `enet_time_get`, `enet_host_random_seed`,
`enet_initialize`) instead, so ENet cannot create, poll or close an
operating-system socket. The two upstream platform files remain only so tests
can build a native ENet peer with real sockets.

WaterWall relies on these upstream details. Re-check them when the pin moves:

- `enet_host_service(host, event, 0)` returns before it reaches `enet_socket_wait`.
- The protocol core calls only `enet_socket_create`, `enet_socket_bind`,
  `enet_socket_get_address`, `enet_socket_set_option`, `enet_socket_destroy`,
  `enet_socket_send`, `enet_socket_receive` and `enet_socket_wait`.
- `ENetHost.mtu`, `ENetHost.maximumPacketSize` and `ENetHost.maximumWaitingData`
  are assigned directly after `enet_host_create`.
- `ENetPeer.state`, `ENetPeer.lastReceiveTime` and `ENetPeer.pingInterval` are
  read to schedule service calls, and `ENetHost.peers[0]` is the session's peer.
- `enet_peer_has_outgoing_commands`, `enet_malloc` and `enet_free` are declared
  `extern` rather than `ENET_API`, and the driver calls them.
- A received reliable packet carries `ENET_PACKET_FLAG_RELIABLE` in its flags.

To refresh: copy the listed files from the new upstream commit and update the pin
above. Check whether upstream already provides reassembly initialization,
receive-queue allocation accounting, bounded peer timing and bandwidth
arithmetic. Retain each local patch still needed, then update this record and
`radkesvat_changes.txt`.
Replace the digests in
`tests/enet_vendor_source_policy_test.py` with the final vendored contents and run
the `waterwall.enet_*` tests.
