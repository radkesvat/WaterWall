# ENet in WaterWall

Upstream: https://github.com/lsalzman/enet
Pinned commit: `5a9c537fd464b3c6d3c55e1d3bd47588faf71b42` (2026-06-23), version 1.3.18.
License: MIT; see `LICENSE`.

This directory is an unmodified copy of the upstream files WaterWall uses:

- `callbacks.c`, `compress.c`, `host.c`, `list.c`, `packet.c`, `peer.c`, `protocol.c`
- `unix.c`, `win32.c`
- `include/enet/*.h`
- `LICENSE`

Local changes: none. `tests/enet_vendor_source_policy_test.py` holds the SHA-256
of every file at the pinned commit and fails when one differs or when another C
source or header appears here. No download occurs during builds. The local
`.clang-format` disables formatting so the files stay byte-identical.

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

To refresh: copy the listed files from the new upstream commit, update the pin
above, replace the digests in `tests/enet_vendor_source_policy_test.py`, and run
the `waterwall.enet_*` tests.
