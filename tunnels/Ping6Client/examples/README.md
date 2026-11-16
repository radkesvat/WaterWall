# Ping6 over IPv4 tunnel examples

These two directories form one point-to-point packet tunnel. Each inner IPv4
packet travels as the data of an ICMPv6 Echo Request inside an outer IPv4 packet
whose Protocol field is `58`. No IPv6 network is needed anywhere on the path.

```text
client host: TunDevice 10.58.0.1/30 -> Ping6Client -> RawSocket
server host: RawSocket -> Ping6Server -> TunDevice 10.58.0.2/30
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
| `192.0.2.10` | Client's public IPv4 address | client `local-ipv4`; server `peer-ipv4` and `capture-ips` |
| `198.51.100.10` | Server's public IPv4 address | client `peer-ipv4` and `capture-ips`; server `local-ipv4` |

Each side's `local-ipv4` must be an address the peer can reach, and its
`capture-ips` must name the peer. Addresses are plain dotted quads.

`RawSocket` sends carriers through the host's ordinary route to the peer. On a
host with several uplinks, set `local-ipv4` to the address of the interface that
route uses; carriers sent from another interface's address normally do not
arrive.

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

The wrapper adds 28 bytes: a 20-byte IPv4 header and an 8-byte ICMPv6 Echo
header. The largest inner packet is 1472 bytes and the largest carrier is 1500
bytes, which is why both examples set `device-mtu` to `1472`. If the path between
the hosts has a smaller MTU, use that MTU minus 28. Outer carriers are sent with
DF set and are never fragmented by Ping6; inner fragments are carried unchanged
because both devices use `fragment-policy: "preserve-fragments"`.

## Optional settings

- `send-replies: true` makes an endpoint answer each received Echo Request with
  an exact Echo Reply before delivering the inner packet. It is independent on
  each side and off by default. Delivery never waits for a reply.
- `local-ipv6` and `peer-ipv6` replace the default `::ffff:<ipv4>` checksum
  pseudo-addresses. Set them explicitly, mirrored on both sides, when address
  translation makes the two hosts see different outer IPv4 addresses.
- `identifier`, `sequence-start`, `ttl` and `tos` shape the outer headers. See
  the [Ping6Client](../description.md) and
  [Ping6Server](../../Ping6Server/description.md) references for all settings.

## What to expect on the host

While running, `RawSocket` installs `iptables` rules that match only the peer's
source address and Protocol `58`, and removes them on an orderly shutdown.
`TunDevice` creates the named interface and removes it on exit. Stop Waterwall
with `SIGTERM` or `Ctrl+C` so both clean up.

Ping6 adds no encryption, authentication, retransmission or congestion control.
It carries IPv4 only.
