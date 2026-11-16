# Ping6 over IPv4 tunnel examples

These two directories form one point-to-point packet tunnel. Each native IPv4
packet reuses its header with Protocol `58`, followed by an ICMPv6 Echo header,
the native body and a final byte saving the original protocol. No IPv6 network is needed anywhere on the path.

```text
client host: TunDevice 10.58.0.1/30 -> Ping6Client -> IpOverrider -> RawSocket
server host: RawSocket -> IpOverrider -> Ping6Server -> TunDevice 10.58.0.2/30
```

| Directory | Role |
| --- | --- |
| [client-tun](client-tun/config.json) | Client side, with its own `core.json` |
| [server-tun](../../Ping6Server/examples/server-tun/config.json) | Server side, with its own `core.json` |

Ping6 is not wire-compatible with `PingClient`/`PingServer`; both ends must run
the Ping6 pair.

## Requirements

- Linux on both hosts, started as root or with `CAP_NET_ADMIN` and `CAP_NET_RAW`.
- `/dev/net/tun`, and `iptables` with the `bpf` match and the `NFQUEUE` and `CT`
  targets, which `RawSocket` uses for capture.
- The two hosts reach each other over IPv4, and every firewall and provider on
  the path passes IPv4 Protocol `58` in both directions. Filters that only expect
  TCP, UDP and ICMP may drop it.

## Configure

Replace the documentation addresses in both `config.json` files:

| Placeholder | Meaning | Appears in |
| --- | --- | --- |
| `192.0.2.10` | Client's public IPv4 address | client outgoing IpOverrider rule; server outgoing destination and capture filter |
| `198.51.100.10` | Server's public IPv4 address | server outgoing IpOverrider rule; client outgoing destination and capture filter |

The four IpOverrider rules are independent:

| Instance/direction | Source after rewrite | Destination after rewrite |
| --- | --- | --- |
| Client upstream, outgoing carrier | 192.0.2.10 | 198.51.100.10 |
| Client downstream, incoming carrier | 10.58.0.2 | 10.58.0.1 |
| Server upstream, incoming carrier | 10.58.0.1 | 10.58.0.2 |
| Server downstream, outgoing carrier | 198.51.100.10 | 192.0.2.10 |

These teaching rules apply to this point-to-point TUN pair, not every native
destination. Choose your own address and routing policy. RawSocket captures the
peer's network address and protocol 58. Both configurations set
`"opaque-flow-mode": "peer"`; the intervening IpOverrider prevents `auto` from
recognizing a directly adjacent Ping decoder. The public peer must remain
reachable over the ordinary interface, outside the TUN route.

## Run and verify

Run Waterwall from each example directory so it loads the local `core.json`.
There is no handshake, so the start order does not matter:

```bash
cd tunnels/Ping6Server/examples/server-tun && /path/to/Waterwall
```

```bash
cd tunnels/Ping6Client/examples/client-tun && /path/to/Waterwall
```

Then, on the client host:

```bash
ping 10.58.0.2
```

To watch the carriers on either host:

```bash
tcpdump -ni any 'ip proto 58'
```

`tcpdump` labels these packets `[ICMPv6 requires IPv6] (invalid)` because the
ICMPv6 message sits directly in IPv4. That label is expected.

`route-table: "off"` installs no routes, so only the two `/30` addresses use the
tunnel. To carry other traffic, add your own routes through the peer's TUN
address or use the TunDevice route settings, and keep the peer's public address
on the ordinary interface so carriers cannot loop back into the TUN.

## Sizes

The user is responsible for configuring a native MTU that leaves room for all
chain overhead and the actual network path. Ping/Ping6 add nine bytes and drop
native packets exceeding the 1,500-byte carrier ceiling after encoding. They do
not discover or negotiate MTU, adjust MSS, segment, or fragment packets. Both
entry points reject IP fragments; configure packet adapters to reassemble
fragments before these nodes. Setting `preserve-fragments` does not make fragments
acceptable.

Both examples set `device-mtu` to 1491, the maximum complete native IPv4 packet
including IP and transport headers. A 1492-byte native packet is refused. For a
smaller path use its MTU minus nine and any other chain overhead. Applicable
ConnectionToPackets/PacketsToConnection `mtu` and core `misc.mtu` settings also
need that budget. Both packet adapters explicitly use `"fragment-policy": "reassemble"`.
DF alone is accepted and preserved; MF or nonzero offset is rejected before repair.

## Optional settings and checksum policy

- `send-replies: true` independently enables exact replies; default false.
  Replies include the trailer, reverse received addresses, use TTL 64 and copy
  TOS. Local data in either direction always uses a fresh Echo Request.
- `local-ipv6` and `peer-ipv6` independently default to `::`. They are checksum
  inputs only, unrelated to IPv4 addresses. Explicit peers normally mirror them.
  Strict bare IPv6 parsing supports compressed IPv4 tails but rejects brackets,
  zones, prefixes, embedded NULs and malformed text.
- `identifier` and `sequence-start` control Echo request identity. There are no
  `local-ipv4`, `peer-ipv4`, `ttl` or `tos` settings on Ping6.

TCP/UDP checksums have their IPv4 address contributions normalized to zero/zero
before wrapping and restored for the final addresses after decoding. Disabled
UDP checksum zero and invalid residuals remain intact absent explicit native
repair; carrier repair affects visible checksums only. Opaque protocols may
protect address/header fields themselves, so address rewriting is not universally
safe. Transit header changes survive. See the
[Ping6Client](../description.md) and [Ping6Server](../../Ping6Server/description.md)
references for structural checks, bounded correlation and replay behavior.

The trailer is not a signature. Ordinary Echo payloads may match this format.
Select a dedicated carrier stream and one logical peer per node; address filters
do not authenticate peers or distinguish all ordinary pings from data.

## What to expect on the host

While running, `RawSocket` installs `iptables` rules that match only the peer's
source address and Protocol `58`, and removes them on an orderly shutdown.
`TunDevice` creates the named interface and removes it on exit. Stop Waterwall
with `SIGTERM` or `Ctrl+C` so both clean up.

Ping6 adds no encryption, authentication, retransmission or congestion control.
It carries IPv4 only.
