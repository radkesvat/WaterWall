# VMess client interoperability

`tests/cmake/integration/vmess.cmake` registers `waterwall.vmess_client_*` in
the existing functional namespace lane. The owning script is
`tests/vmess_client_interop.py`; it generates configuration files in its private
run directory and retains logs and inputs on failure.

The topology is a TCP or UDP application listener, VmessClient, optional
HTTP/1.1 WebSocket and TLS client nodes, and a TCP connector. Its peer is either
the checksum-pinned V2Ray 5.53.0 VMess inbound with freedom outbound, or the real
WaterWall VmessServer with local UUID or AuthenticationClient-managed users.
All destinations are local TCP/UDP echo peers on IPv4/IPv6 loopback. Domain
cases use `localhost`, including fixed and SOCKS-supplied destinations and all
existing client DNS strategies. TLS composition uses the repository's local
test certificate with verification disabled and only HTTP/1.1 ALPN offered.

Provision the reference before entering private namespaces:

```sh
cmake --build --preset linux --target waterwall_vmess_reference
ctest --preset linux -R '^waterwall\.vmess_client_' --output-on-failure
```

The reference setup reuses `tests/provision_vmess_reference.py`, with no network
downloads inside tests. Both endpoint directions are registered independently
when their required targets exist. Client-only builds retain the reference
server matrix without requiring VmessServer or managed-authentication targets.

TCP success means exact server-first greeting, 256 KiB plus a trailing marker in
each direction, and observed full close during orderly SIGTERM shutdown (143).
Greeting before application input proves header-only first-payload bootstrap.
The silent case leaves the backend silent before the first greeting; the early
close case closes it without application bytes. UDP verifies five nonempty
datagrams and their replies individually. Empty VMess records denote termination.

The matrix includes all four TCP security modes, three framed UDP modes, every
encrypted framing option bitmask, NONE's ordinary/masked lengths and UDP global
padding, raw TCP/TLS/WebSocket/WebSocket-over-TLS, two-worker fragmented response
headers, corrupted authenticated response lengths, wrong UUID and managed
disabled/expired/exhausted accounts. Rotation uses the real administration API,
waits for AuthenticationClient's applied configuration revision, then proves old
UUID rejection and new UUID acceptance without retrying an administrative write.
Rejected identities/accounts must not contact a protected destination. The
large TCP burst is sent only after the greeting, preserving the server's
existing 64 KiB pending-authentication admission limit.

Native VMess coverage separately owns deterministic callback reentry, queue
budgets, all response split boundaries, option commands, malformed headers,
timers, exact nonce limits and owner-line balance. These functional cases
require native Linux namespaces (`unshare`, `ip`), Python 3, IPv6 loopback, the
built WaterWall executable and the pinned reference binary. Each CTest case
has a 75-second bound; missing prerequisites are unavailable validation, never a
successful interoperability result.
