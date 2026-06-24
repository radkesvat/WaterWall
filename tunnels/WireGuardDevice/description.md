# WireGuardDevice Node

`WireGuardDevice` is Waterwall's in-chain WireGuard implementation.

It is a pure packet tunnel created with `packettunnelCreate()`, so it does not add per-line tunnel state of its own. Its inner packet side runs on the chain's worker packet lines, while its outer transport side uses one normal companion line per worker so transport-side nodes do not mistake WireGuard UDP messages for inner packet-line traffic. It transforms packet payload between:

- inner IP packets on one side
- raw WireGuard handshake / transport messages on the other side

Important design point:
`WireGuardDevice` does not open a UDP socket by itself, and it does not create an OS WireGuard interface.

In Waterwall, the usual split is:

- `UdpStatelessSocket` owns the outer UDP socket
- `WireGuardDevice` owns WireGuard crypto, peer state, routing, handshake, keepalive, and rekey logic
- `TunDevice`, `RawSocket`, `PacketsToConnection`, or another packet-oriented node owns the inner packet side

## What It Does

- encrypts inner IPv4 or IPv6 packets into WireGuard transport packets
- decrypts valid WireGuard transport packets back into inner IP packets
- handles WireGuard handshake initiation, handshake response, cookie reply, and transport-data messages
- supports multiple peers in one tunnel instance
- picks the outbound peer using longest-prefix `AllowedIPs` matching
- validates inbound decrypted packet source addresses against that peer's configured `AllowedIPs`
- updates a peer's current endpoint from authenticated inbound traffic
- runs a periodic device loop for keepalive, handshake retry, rekey, and session cleanup

## What It Does Not Do

This node is not a `wg-quick` clone.

The current implementation does not parse or manage things like:

- interface `Address`
- interface `ListenPort`
- interface `MTU`
- routing `Table`
- `PostUp` / `PostDown`
- system firewall or NAT setup

Those concerns belong to other Waterwall nodes or to the host system.

In practice:

- local UDP bind address and port belong to `UdpStatelessSocket`
- inner interface IPs usually belong to `TunDevice` or another packet-side component

## Typical Placement

The intended shape is:

- packet side node -> `WireGuardDevice` -> `UdpStatelessSocket`

or the reverse:

- `UdpStatelessSocket` -> `WireGuardDevice` -> packet side node

Common packet-side neighbors include:

- `TunDevice`
- `RawSocket`
- `PacketsToConnection`
- `PacketsToStream` / `StreamToPackets`
- packet-mode `TesterClient` / `TesterServer`

## Transport-Side Detection

During `onPrepare`, `WireGuardDevice` decides which side carries outer WireGuard UDP message bodies.

If `settings.transport-direction` is set, that explicit value is used and no topology search is performed.

If it is not set, the tunnel searches outward in both chain directions:

- first for `UdpStatelessSocket`, across all reachable `next` tunnels and all reachable `prev` tunnels
- if no `UdpStatelessSocket` is found, for a tunnel whose node has `kNodeLayer4` enabled in `layer_group`

If `UdpStatelessSocket` is found only on one side, that side becomes the transport side. If `UdpStatelessSocket` is found in both directions, `transport-direction` is mandatory because the topology is ambiguous.

If no UDP stateless socket is found, the Layer 4 search is a compatibility fallback. A single Layer 4 side is selected; otherwise the tunnel keeps the historical default of treating `next` as the transport side.

## Configuration Example

```json
{
  "name": "wg-device",
  "type": "WireGuardDevice",
  "settings": {
    "privatekey": "<base64-32-byte-private-key>",
    "transport-direction": "next",
    "peers": [
      {
        "publickey": "<base64-32-byte-peer-public-key>",
        "allowedips": "10.44.0.2/32,10.44.1.0/24,fd00::2/128",
        "endpoint": "vpn.example.com:51820",
        "presharedkey": "<optional-base64-32-byte-psk>",
        "persistentkeepalive": 25
      }
    ]
  },
  "next": "udp-edge"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"WireGuardDevice"`.

### `settings`

- `privatekey` `(string)`
  Base64-encoded 32-byte WireGuard private key for this device.

- `peers` `(array)`
  Array of peer objects.

  Current implementation rules:
  - must be a non-empty array
  - maximum peer count is `32`

## Optional Settings Fields

- `transport-direction` `(string)`
  Explicitly selects which side of `WireGuardDevice` carries outer WireGuard transport packets.

  Accepted values:
  - `"next"` or `"up"` or `"upstream"`: the transport side is the next/upstream side
  - `"prev"` or `"down"` or `"downstream"`: the transport side is the previous/downstream side

  When omitted, `WireGuardDevice` auto-detects the transport side by searching for `UdpStatelessSocket` in both directions, then falls back to Layer 4 node detection. Set this field when both directions contain `UdpStatelessSocket` or when the chain shape is intentionally unusual.

### Per-peer required fields

- `publickey` `(string)`
  Base64-encoded 32-byte WireGuard public key for that peer.

- `allowedips` `(string)`
  One or more CIDRs separated by commas.

  Examples:
  - `"10.44.0.2/32"`
  - `"10.44.0.0/24,10.45.0.0/24"`
  - `"10.44.0.2/32,fd00::2/128"`

  Current implementation rules:
  - at least one entry is required
  - spaces are tolerated and stripped
  - IPv4 and IPv6 entries are both accepted
  - maximum entries per peer is `16`

- `endpoint` `(string)`
  Peer endpoint in one of these forms:
  - `"host:port"`
  - `"ipv4:port"`
  - `"[ipv6]:port"`

  The hostname is resolved during tunnel creation and stored as an IP address.

## Optional Per-Peer Fields

- `presharedkey` `(string)`
  Optional base64-encoded 32-byte preshared key.

  If omitted, the peer runs without PSK.

- `persistentkeepalive` `(integer)`
  Keepalive interval in seconds.

  Current implementation rules:
  - valid range: `0` to `65535`
  - default if omitted: `0`
  - `0` means disabled

## Detailed Behavior

### Inner packet side

The non-UDP side of the tunnel is the inner packet side.

When payload arrives from that side:

- the buffer must contain an IPv4 or IPv6 packet
- the destination IP is extracted from the inner packet
- the peer is selected by longest-prefix `AllowedIPs` match
- the packet is encrypted into a WireGuard transport message
- the peer's current endpoint is written into the worker's transport companion line destination routing context
- the resulting WireGuard message is forwarded toward `UdpStatelessSocket`

If no peer matches the destination IP, the packet is dropped.

### Transport packet side

The `UdpStatelessSocket` side is the outer transport side.

When a UDP datagram reaches `WireGuardDevice` from that side:

- the payload is interpreted as a raw WireGuard message body
- message type is detected
- handshake, cookie, and transport-data messages are processed
- valid decrypted data is checked to make sure it is an IP packet
- the inner source IP is checked against that peer's `AllowedIPs`
- only then is the plaintext packet forwarded to the inner packet side

So `AllowedIPs` is used in both directions:

- outbound: destination-based peer selection
- inbound: source-based validation after decryption

That is the cryptokey-routing model WireGuard expects.

### Endpoint update and roaming behavior

Each peer has:

- a configured endpoint from JSON
- a current endpoint used for live traffic

When authenticated inbound packets arrive, the peer's current endpoint is updated to the sender address and port.

This means the tunnel supports the common WireGuard behavior where the live endpoint can move after traffic is received.

If session state later expires hard enough to reset the peer, the code falls back to the configured endpoint again.

### Startup behavior

When the tunnel starts:

- every configured peer is marked active with `wireguardifConnect()`
- the periodic device loop begins
- the loop runs every `400 ms`

That loop is responsible for:

- initial handshake attempts
- keepalive sends
- rekey scheduling
- key/session expiry cleanup

Because of that startup logic, the current implementation requires an `endpoint` for every peer, even if you expect the peer to behave more like a responder at first.

In other words:

- `endpoint` is mandatory today
- later authenticated traffic can still update the live endpoint

## Buffer And Padding Notes

`WireGuardDevice` advertises:

- `required_padding_left = 16`

That matches the prepend requirement for the 16-byte WireGuard transport-data header before ciphertext is forwarded to the UDP side.

The authentication tag is appended at the tail, not prepended at the head.

So in normal Waterwall chains:

- left padding is used for the transport header
- tail growth is used for ciphertext expansion and auth tag space

## Example Layouts

### 1. TUN to UDP WireGuard client side

```json
{
  "name": "tun0",
  "type": "TunDevice",
  "settings": {
    "device-name": "tun0",
    "device-ip": "10.44.0.1/24"
  },
  "next": "wg-client"
}
```

```json
{
  "name": "wg-client",
  "type": "WireGuardDevice",
  "settings": {
    "privatekey": "<client-private-key>",
    "peers": [
      {
        "publickey": "<server-public-key>",
        "allowedips": "10.44.0.2/32,10.55.0.0/16",
        "endpoint": "198.51.100.20:51820",
        "persistentkeepalive": 25
      }
    ]
  },
  "next": "udp-client"
}
```

```json
{
  "name": "udp-client",
  "type": "UdpStatelessSocket",
  "settings": {
    "listen-address": "0.0.0.0",
    "listen-port": 51820
  }
}
```

Conceptually:

- inner IP packets come from `TunDevice`
- `WireGuardDevice` encrypts them
- `UdpStatelessSocket` sends them as UDP datagrams

### 2. UDP edge to inner packet side on the peer

```json
{
  "name": "udp-server",
  "type": "UdpStatelessSocket",
  "settings": {
    "listen-address": "0.0.0.0",
    "listen-port": 51820
  },
  "next": "wg-server"
}
```

```json
{
  "name": "wg-server",
  "type": "WireGuardDevice",
  "settings": {
    "privatekey": "<server-private-key>",
    "peers": [
      {
        "publickey": "<client-public-key>",
        "allowedips": "10.44.0.1/32",
        "endpoint": "203.0.113.10:51820"
      }
    ]
  },
  "next": "tun-out"
}
```

Conceptually:

- UDP datagrams arrive at `UdpStatelessSocket`
- `WireGuardDevice` decrypts and authenticates them
- inner packets continue to `TunDevice`, `RawSocket`, `PacketsToConnection`, or another packet-side node

### 3. Verified loopback-style packet test shape

The repository already tests this pattern:

- packet-mode `TesterClient`
- `WireGuardDevice`
- `UdpStatelessSocket`

paired against:

- `UdpStatelessSocket`
- `WireGuardDevice`
- packet-mode `TesterServer`

That layout is useful as a minimal reference when you want WireGuard transport over UDP without introducing a real TUN interface yet.

## Notes And Caveats

- This is a packet tunnel, not a connection tunnel.
- The inner side uses worker packet lines supplied by the chain and should not be treated like a closable per-connection adapter.
- The outer WireGuard transport side uses normal worker-local companion lines owned by `WireGuardDevice`; those lines are not packet lines and are torn down by `WireGuardDevice`.
- The tunnel itself does not add a UDP header; that belongs to `UdpStatelessSocket`.
- Hostname endpoints are resolved once during startup, not continuously re-resolved later.
- Keep the chain shape unambiguous by placing `UdpStatelessSocket` on only one side, or set `transport-direction` explicitly.
- Outbound routing depends entirely on `AllowedIPs`; if your inner destination addresses do not match a peer, traffic is dropped.
- Inbound plaintext is forwarded only if the decrypted source address is allowed for that peer.
