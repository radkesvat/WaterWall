# JunkDatagramSender Node

`JunkDatagramSender` is a composable middle tunnel that injects generated junk datagram payloads when a line is initialized. It is intended for camouflage and protocol-noise experiments around UDP-like paths, while still preserving Waterwall's normal line lifecycle and callback directions.

The node forwards `Init` first so the next tunnel has created its per-line state, then sends the generated junk payloads before this line's real payload callbacks are forwarded. Regular payload, `Est`, pause/resume, and finish callbacks are otherwise pass-through.

## Configuration Example

```json
{
  "name": "junk",
  "type": "JunkDatagramSender",
  "settings": {
    "packet-count-perline-min": 2,
    "packet-count-perline-max": 5,
    "selected-protocols": ["dns", "ntp", "quic-http3", "rtp-rtcp-srtp"],
    "keep-sending-max-ms": 1500
  },
  "next": "udp-out"
}
```

## Settings

- `packet-count-perline-min` `(integer, optional)`
  Minimum number of junk packets generated for each initialized line.
  Default: `1`

- `packet-count-perline-max` `(integer, optional)`
  Maximum number of junk packets generated for each initialized line.
  Default: `1`

- `selected-protocols` `(array of strings, optional)`
  Protocol module names eligible for packet generation. If omitted, all implemented modules are eligible. Use `all` to explicitly enable all implemented modules.

- `keep-sending-max-ms` `(integer, optional)`
  Default `0` disables delayed copies. When greater than zero, each generated junk packet is duplicated and scheduled once at a random delay between `1` and this value.

## Protocol Names

Accepted canonical names are:

- `dns`
- `dhcp`
- `ntp`
- `quic-http3`
- `rtp-rtcp-srtp`
- `stun-turn-ice`
- `mdns`
- `snmp`
- `syslog`
- `ipsec-nat-t`
- `sip`

Some shorter aliases are accepted, such as `quic`, `http3`, `rtp`, `stun`, and `ipsec-natt`.

## Disabled Protocol Names

These protocol modules are intentionally disabled until their packet generators are implemented. If a user lists one in `selected-protocols`, configuration fails.

- `tftp`
- `ssdp`
- `radius`
- `gtp-u`
- `gtpu`
- `game-udp-protocols`
- `game-udp`
- `game`
- `coap`

## Module Contract

Each protocol module lives in `modules/` and exposes one generator:

```c
bool junkdatagramsender<Protocol>Generate(sbuf_t *buf, const junkdatagramsender_module_args_t *args);
```

The generator receives an already allocated `sbuf_t`, writes one datagram payload into it, sets the buffer length, and returns whether generation succeeded. The module owns only the bytes it writes; the node owns forwarding, scheduling, and buffer reuse.

The DNS module currently builds a real DNS query UDP payload with a question and optional EDNS(0) OPT record. DHCP builds valid-looking DHCPv4 client messages, NTP builds valid-looking NTP client requests, QUIC/HTTP3 builds QUIC Initial-like datagrams with HTTP/3 ALPN, RTP/RTCP/SRTP builds RTP media, RTCP control, and SRTP-shaped payloads, STUN/TURN/ICE builds connectivity-check and relay-control messages, mDNS builds multicast DNS query and announcement payloads, SNMP builds v1/v2c manager requests, Syslog builds RFC3164/RFC5424 messages, IPsec NAT-T builds keepalive, IKEv2, and ESP-in-UDP payloads, and SIP builds valid-looking SIP requests and responses. The disabled modules remain structural placeholders for future implementation and are not selectable by users.

## Lifecycle Notes

`JunkDatagramSender` does not store per-line tunnel state. Delayed payloads are scheduled with Waterwall's `lineScheduleDelayedTaskWithBuf()`, so the core line scheduler owns the temporary line reference and releases the buffer if the line has closed before the task runs.

Packet helper lines are not destroyed by this tunnel during runtime, and junk generation is skipped on worker packet lines so a layer-3 chain bootstrap does not emit connection-style junk payloads.
