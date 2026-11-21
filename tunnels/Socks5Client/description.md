<!--
Documentation version: 159
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/Socks5Client.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/Socks5Client.mdx, and all files must keep the same documentation version.
-->

# Socks5Client Node

## Overview

`Socks5Client` is a stream middle-tunnel that speaks the client side of the SOCKS5 protocol.

It reads its target settings from JSON, sends the SOCKS5 greeting and optional username/password authentication, then
submits a SOCKS5 command for the configured target destination. It supports TCP `CONNECT` and UDP `ASSOCIATE`.
Upstream application payload is held until the proxy accepts the request.

CONNECT uses a stream on both sides. UDP ASSOCIATE takes application
datagrams and opens two carrier lines, a stream for control and a datagram
line for relay traffic. The configured carrier path must support both lines.

## Typical placement

TCP proxy chain:

`TcpListener <-> Socks5Client <-> TcpConnector`

UDP-capable proxy chain:

`TcpUdpListener <-> Socks5Client <-> TcpUdpConnector`

Important:

- `Socks5Client` can use either fixed JSON target values or the incoming `line->dest_ctx`
- it prepares the final SOCKS target during `Init` and mirrors that result into `lineGetDestinationAddressContext(line)`
- the actual connection to the SOCKS proxy itself is still made by the next adapter, usually a connector with a constant
  proxy address/port
- UDP mode creates a TCP control line for `UDP ASSOCIATE` and a UDP relay line for SOCKS UDP datagrams, so the next
  adapter should be `TcpUdpConnector` when UDP is used


## Minimal practical example

This is a **node fragment** for TCP CONNECT. `proxy-transport` must connect to
your SOCKS5 proxy endpoint; the target below is the requested remote service.

### Fixed target example

```json
{
  "name": "socks-client",
  "type": "Socks5Client",
  "settings": {
    "address": "example.com",
    "port": 443,
    "protocol": "tcp",
    "dns-behaviour": {"resolve": true, "strategy": "prefer-ipv4"}
  },
  "next": "proxy-transport"
}
```

With local domain resolution enabled, the internal `DomainResolver` resolves `example.com` before the SOCKS request is
sent. If an IPv4 answer is available, the SOCKS request carries the IPv4 address. Otherwise it falls back according to
the selected strategy.


## Configuration

### Required JSON Fields

- `settings.address`
  The target host or IP that should appear in the SOCKS5 request.
  It may be a literal host/IP or `"dest_context->address"`.

- `settings.port`
  The target port that should appear in the SOCKS5 request.
  It may be a number or `"dest_context->port"`.

### Optional JSON Fields

- `settings.protocol`
  Selects the SOCKS command and the protocol placed in `lineGetDestinationAddressContext(line)`.

  Supported values:

  - `"tcp"` or `"connect"`
    Require an offer that allows TCP and send a SOCKS5 `CONNECT` request.
  - `"udp"` or `"udp-associate"`
    Require an offer that allows UDP, negotiate SOCKS5 `UDP ASSOCIATE`, and send payloads as SOCKS UDP
    datagrams.
  - `"dest_context->protocol"` or `"line->dest_ctx->protocol"`
    Choose from the incoming destination offer. A TCP choice sends CONNECT, and a UDP choice negotiates UDP ASSOCIATE.

  A fixed protocol must be in the unpinned destination offer.
  With `dest_context->protocol`, the client follows an exact offer and prefers TCP
  when the line offers both. Missing or invalid offers close the line. A pinned
  DNS or SOCKS relay endpoint supplies its own exact address, port and protocol
  even when the client is configured for a different protocol.

  Default: `"tcp"`

- `settings.user` and `settings.pass`
  Optional SOCKS5 username/password authentication. If one is present, the other must also be present.

- `settings.verbose`
  Enables extra tunnel logging.

- `settings.dns-behaviour`
  Controls local target lookup, address selection and DNS transport. See DNS behaviour below.

### DNS behaviour

Resolving a hostname means looking up its IP address. `Socks5Client` can send
the final target's hostname in the SOCKS5 request, or resolve it locally and
send the selected IP instead. Local resolution runs only for an unresolved
hostname when enabled. Literal IPs and already-resolved targets need no lookup.

This setting concerns the final target reached through the proxy. The following
connector selects the proxy server's address and has its own DNS settings.
Without `dns-behaviour`, local resolution is disabled.

Configure this lookup with `settings.dns-behaviour`:

```json
{
  "dns-behaviour": {
    "resolve": true,
    "mode": "direct",
    "strategy": "prefer-ipv4",
    "servers": ["203.0.113.53:53"]
  }
}
```

The address is a documentation placeholder; replace it with your resolver.

| Field | Meaning |
| --- | --- |
| `resolve` | Required boolean: `true` allows lookup of unresolved hostnames; `false` disables local lookup. |
| `mode` | `native` (default when enabled), `direct`, or `chain`. |
| `strategy` | `core-settings`, `accept-dns-returned-order`, `prefer-ipv4`, `prefer-ipv6`, `only-ipv4`, or `only-ipv6`; omission uses this consumer's default address preference. |
| `servers` | 1–32 numeric IP, IP:port or [IPv6]:port endpoints; required for direct/chain and rejected for native. |
| `dns-next` | Nonempty DNS-entry name for chain only. |

`native` uses core DNS settings and the worker's shared resolver. It is the default
DNS transport when local resolution is enabled.

`direct` sends DNS queries through a private WaterWall TCP/UDP connector to the
servers you specify.

`chain` sends DNS queries through a selected chain. Use a path with encryption,
such as your VPN, to protect those queries; the mode alone does not encrypt them.
The DNS path must carry both UDP queries and TCP fallback. A route or lookup
failure does not switch to native DNS or another mode.

In `chain` mode, omitting `dns-next` sends DNS requests through this proxy client
and its following transport. To use another path, set `dns-next` to a separate
DNS branch that does not already belong to another node. Leave the field omitted
to use this node; do not set it to this node's own name.

The disabled form is exactly `"dns-behaviour": {"resolve": false}`. It rejects `mode`, `strategy`, `servers` and `dns-next`. Empty/null/non-object policies, unknown fields and numeric strategies are rejected. Strategy names use the canonical lowercase strings above. `core-settings` chooses address preference only and never changes DNS transport.

`resolve: false` keeps the hostname in requests that support it. The following connector still selects the independent proxy/VPN endpoint and has its own DNS policy. Use a numeric outer endpoint or an independent bootstrap path.

See [DomainResolver](../../WaterWall-Docs/docs/02-noderefs/DomainResolver.mdx) for native, direct and protected-chain configuration examples and core option limits. This policy controls lookups owned by this node; it does not configure PTC fake DNS, TunDevice system DNS or every DNS source in the program.

## Usage and troubleshooting

### Configuration Example

```json
{
  "name": "socks-client",
  "type": "Socks5Client",
  "next": "proxy-connector",
  "settings": {
    "address": "dest_context->address",
    "port": "dest_context->port",
    "protocol": "tcp",
    "user": "alice",
    "pass": "secret",
    "dns-behaviour": {"resolve": false},
    "verbose": false
  }
}
```

Accepted address keys:

- `address`
- `target-address`
- `target`

Configured domain names must be 1 to 255 bytes long. Longer names are rejected during node creation.

Accepted credential keys:

- `user` or `username`
- `pass` or `password`

### Domain Resolution Example

```json
{
  "name": "socks-client",
  "type": "Socks5Client",
  "next": "proxy-connector",
  "settings": {
    "address": "example.com",
    "port": 443,
    "protocol": "tcp",
    "dns-behaviour": {"resolve": true, "strategy": "prefer-ipv4"}
  }
}
```

With this setting, `Socks5Client` resolves `example.com` before sending the SOCKS5 command. If an IPv4 answer is
available, the SOCKS5 request encodes that IPv4 address instead of the domain name. If no IPv4 answer is available, it
falls back to IPv6.

### Notes And Caveats

- SOCKS5 UDP fragmentation is not reassembled; datagrams with `FRAG != 0` are ignored conservatively.
- UDP mode expects the proxy listener topology to make the UDP associate reply address reachable from the client.
- A server may return a dedicated dynamic UDP port, so firewall and NAT policy must permit the returned relay endpoint,
  not only the TCP control port.
- `required_padding_left` is set for the worst-case SOCKS5 UDP header so UDP mode can prepend datagram headers without
  breaking Waterwall buffer-padding assumptions.

## Advanced behavior

### Behavior

Application lines enter `Socks5Client` through upstream `Init`. Downstream `Init` is disabled for every line role,
including UDP application, control, and relay lines; receiving it logs a fatal diagnostic and terminates the process
through `abortProgramNow(1)`. Downstream `Est` and payload callbacks remain supported for proxy replies and relay data.

- target preparation mirrors the configured target into the line destination context before the protocol core starts,
  either by the internal resolver prepare hook or directly during client init when local DNS resolution is disabled.
- the resolved SOCKS target is kept in `Socks5Client` line state so the proxy transport connector can rewrite
  `line->dest_ctx` without changing the later SOCKS request.
- if `dns-behaviour.resolve` is true and the target is an unresolved hostname, DNS resolution happens before the SOCKS5 greeting
  is sent by the internal `DomainResolver`.
- if `address` and/or `port` use `dest_context`, the incoming line destination is used as the SOCKS target source
- if `protocol` uses `dest_context->protocol`, the incoming destination protocol is read before any configured
  address/port rewrite
- after next `Init` returns with the line still live, the client submits the SOCKS5 method greeting once. A connecting
  `TcpConnector` queues it until the connection succeeds. On the owned TCP control line for UDP, write pressure can
  defer the greeting.
- `DownStreamEst` forwards transport readiness immediately, independently of negotiation. Direct TCP forwards repeated
  notifications and the UDP control line maps readiness once to its application.
- `DownStreamPayload` consumes method, auth, and command replies from the proxy.
- `UpStreamPayload` is buffered until the SOCKS5 command succeeds.
- a successful TCP proxy reply releases the bounded application FIFO in order without waiting for Resume
- TCP source pressure combines the pending/draining application FIFO with the latest next-side Pause/Resume;
  Resume reaches the source only after both holds clear, while duplicate pressure notifications pass through
  when no local hold remains
- after successful TCP negotiation, all retained input/output has drained and both source-pressure holds are released,
  the client destroys its line state and permanently bypasses itself; later callbacks pass directly between neighbors
- on handshake failure it destroys local state first, then closes both directions
- in UDP mode, upstream payload is wrapped in a SOCKS5 UDP request header and sent through the UDP relay line
- in UDP mode, downstream relay datagrams have the SOCKS5 UDP header stripped before payload is forwarded back
- in UDP mode, the relay line uses the `BND.ADDR` and `BND.PORT` returned by the successful `UDP ASSOCIATE` reply;
  it does not reuse the TCP control port or overwrite the negotiated endpoint with the next connector's static proxy port

The negotiated relay authority survives `Router`/sniffer clearing of observed
application-protocol metadata. The outbound UDP adapter consumes it exactly once,
then clears the internal marker so it cannot affect later unrelated routing.

## Implementation details

### Splice Support

Socks5Client supports splice-backed TCP payloads. During method, authentication
and command negotiation, complete proxy-reply deliveries are materialized with
`sbufEnsureOrdinary()` before parser or nested-input admission. After negotiation,
TCP payloads and necessary opaque FIFO entries can retain their original buffers.
The incomplete-handshake and application-backlog limits remain separate.

UDP application, TCP control and UDP relay lines request ordinary reads in both
directions for their lifetimes. UDP target preparation sets the application
preference before local DNS can retain input. Preferences are advisory and do not
propagate between associated lines; every UDP datagram is still materialized
before application retention, header decoding or framing. Ordinary input passes
through the helper unchanged. TCP CONNECT lines do not request ordinary reads.

The internal DomainResolver remains splice-capable. Actual activation requires
an eligible finalized chain and `misc.splice`; a TLS or other blocking node still
disables splice for the entire payload chain.

### Node Metadata

Source-backed metadata:

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagSupportsSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `262` bytes |

Transport `Est` does not mean SOCKS negotiation has succeeded. Application payload can be accepted after Init;
the real protocol backlog is bounded at 2 MiB logical bytes and 8 MiB queue charge. TCP greeting and ready application/reply output
do not wait for Resume. The first retained application input pauses its source; the source resumes when the
older FIFO drains and next-side transport pressure has cleared. Neither hold can release the other.
TCP receive Pause also reaches the next adapter during negotiation; its issuer must arrange Resume or close.
For UDP, control and relay write pressure combine; one Resume cannot clear the other's outstanding Pause.
UDP application backlog release and the owned control greeting continue to honor that boundary pressure,
and application receive pressure is mapped to the relay line after its Init.
UDP application, control and relay lines remain active for framing, association ownership and pressure mapping.
The 4,096-byte bound applies only to incomplete reply metadata; a completed reply
may arrive with a larger application body. Nested reply processing is serialized,
with response bytes kept in FIFO order. Necessary retained response input shares
a 2 MiB logical-byte / 8 MiB queue-charge downstream budget and drains after older reply input, including through Pause; ready TCP
forwarding stays synchronous. Empty proxy TCP input is ignored, and unused TCP tails on
an established UDP control line are discarded. Ordering queues allocate backing
storage on first use; UDP application and relay lines do not allocate handshake
stream storage.
