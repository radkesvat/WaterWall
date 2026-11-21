<!--
Documentation version: 154
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/EncryptionClient.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/EncryptionClient.mdx, and all files must keep the same documentation version.
-->

# EncryptionClient

## Overview

`EncryptionClient` applies AEAD encryption on upstream traffic and decrypts downstream traffic carried in TLS-like application-data records.

Normal lines carry a byte stream or complete datagrams. Set `packet-mode: true`
for the separate IPv4 packet profile described below.

Each normal line selects and records its framing from the destination
offer at `Init`. TCP selects the stream codec, UDP selects the datagram
codec, and an offer of both selects TCP. The selected transport is published
before the next node receives `Init`.

## Typical placement

Recommended chain usage:

- Client side: `TcpListener -> EncryptionClient -> TcpConnector`
- Server side counterpart: `TcpListener -> EncryptionServer -> TcpConnector`

## Minimal practical example

These are node fragments; define the referenced neighboring nodes in the surrounding configuration.

### Example

```json
{
  "name": "enc-client",
  "type": "EncryptionClient",
  "settings": {
    "algorithm": "chacha20-poly1305",
    "password": "replace-with-a-strong-secret",
    "salt": "chain-A",
    "kdf-iterations": 20000,
    "max-frame-size": 16356
  }
}
```

## Configuration

### Settings

- `packet-mode` (boolean, optional): `false` by default; `true` selects IPv4 payload encryption.
- `algorithm` (string or number, optional): normal lines use `chacha20-poly1305` (default) or `aes-gcm`. Packet mode uses only `xchacha20-poly1305` (its default).
- `password` (non-empty string, required): shared secret used for key derivation. On normal lines the limit is 32 bytes when `kdf-iterations` is greater than 1.
- `salt` (string, optional): key-derivation salt of at most 32 bytes in either mode, default `waterwall-encryption`.
- `kdf-iterations` (number, optional): key derivation rounds, default `12000`
- `max-frame-size` (number, optional): maximum plaintext frame size in bytes, default `16356`

## Advanced behavior

### Packet Mode

Set `"packet-mode": true` explicitly when the node receives complete IPv4
packets. This selects Layer-3 metadata and a stateless packet transform instead
of the stream record reader. It is not selected merely because a different part
of the chain has a packet adapter. The default `false` selects normal-line use.

```json
{
  "packet-mode": true,
  "algorithm": "xchacha20-poly1305",
  "password": "replace-with-a-long-random-shared-secret"
}
```

Packet mode accepts only XChaCha20-Poly1305, which is also its default when
`algorithm` is omitted. Normal lines use ChaCha20-Poly1305 or
AES-GCM. `max-frame-size` belongs to normal-line mode
and is rejected in packet mode; packet data is never split into records.
`password`, `salt` and `kdf-iterations` still select the shared base key. Packet
mode hashes the password with SHA-256 for its repeated BLAKE2s KDF key, allowing
long passwords without exceeding BLAKE2s key limits, then derives separate keys
for client-to-server and server-to-client traffic.
Both peers must agree on the password, salt and iteration count.

For each complete, unfragmented IPv4 TCP or UDP packet:

```text
before: [IPv4 header][TCP/UDP header][transport payload]
after:  [IPv4 header][TCP/UDP header][24-byte nonce][encrypted payload][16-byte tag]
```

The actual IPv4 IHL and TCP data offset locate the payload, so IP and TCP options
remain visible and preserved. There is no TLS-like header and no extra IP header.
Exactly one packet is produced per accepted input, including an empty transport
payload. Every encoding uses a fresh nonce from the cryptographic random source;
packets can be lost or reordered without retaining partial data or preventing
later decryption. An empty `sbuf_t` is not a complete packet and is dropped.

IP total length, UDP length and visible checksums are updated; sequence,
acknowledgment, flags, ports and addresses are preserved. IPv4 TCP/UDP checksums
must normally be valid, with disabled UDP checksum zero accepted and preserved.
A pending checksum-repair flag authorizes repair of outgoing checksums and makes
received visible checksums non-authoritative, but never bypasses authentication.
Explicit repair enables a UDP checksum even when its old value was zero.
The packet's exposed protocol is authenticated. Mutable IP/transport fields are
not authenticated, allowing address/port rewriting and normal TTL changes.
Encryption protects the transport payload, not those visible fields or timing.
It does not implement replay rejection.

Both directions reject IPv6, fragments (MF or nonzero offset), malformed lengths,
unsupported visible protocols, trailing buffer bytes, invalid TCP offsets, and
UDP lengths that differ from the IPv4 payload length. DF alone is accepted.
Reassemble fragments before this node. Wrong keys and invalid authentication
tags drop only that packet; the shared packet line stays alive. No failure sends
`Finish` or destroys a packet line.

The format adds **40 bytes**. The final IPv4 packet must fit `65535` bytes, so
its plaintext input can be at most `65495` bytes; the real carrier/device path
can impose a much smaller MTU. The node does not fragment, discover PMTU, adjust
TCP MSS, or recalculate TCP sequence progression for the expanded payload.
It advertises 24 bytes of left padding for the nonce; tag space is managed by
the packet encoder. Native TCP endpoints still own their sequence space, so
this is not a promise of transparent TCP behavior through arbitrary middleboxes.

For FakeTcpHeader, the most convenient setup is its own optional `password`
setting. It inserts and configures the appropriate Encryption node privately,
places encryption after fake-header encoding, and includes the 40 bytes in its
sequence reservations and 1500-byte carrier limit. The protocol byte and original
transport header are then encrypted together behind the visible fake TCP header.
Manually adding a separate Encryption node does not tell FakeTcpHeader to account
for that extra expansion. See the FakeTcpHeader node references for chain order.

The following record framing, frame limits, buffering and stream lifecycle
sections describe `packet-mode: false`. Packet mode uses chain-owned packet
lines, no per-line reader state, and the normal packet-tunnel callback defaults.

### Wire Format

Encrypted payloads are sent as TLS-like application-data records:

- TLS record type `0x17`
- TLS version `0x0303`
- 16-bit record body length
- random nonce followed by AEAD ciphertext and tag

The selected algorithm is configured locally on both peers and is not exposed in the record header.

On a stream, complete received records are drained as they become available; only an incomplete
record remains buffered between callbacks. Once its header is complete, the record
length is checked against `max-frame-size` before waiting for the rest of the body.
Malformed records or AEAD authentication failure close both directions.

### Datagram records

On a datagram line, each admitted plaintext datagram produces one complete
authenticated record in one carrier payload. An empty datagram produces one
33-byte record. The plaintext limit is `max-frame-size`. The default limit
of 16,356 bytes produces a record of at most 16,389 bytes. Budget 33 bytes
of record overhead when setting the limit for a smaller carrier. The sender
drops an oversized datagram whole and
can still send the next valid datagram on the same line.

The receiver validates the header, exact record length and authentication tag
before handing off one plaintext datagram. A truncated record, extra bytes,
multiple records in one delivery or failed authentication closes that line.

## Implementation details

### Node Metadata

Source-backed metadata:

This node explicitly disables splice for the entire chain through
`kNodeFlagBlocksSplice`, even if `kNodeFlagSupportsSplice` is also set.

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagBlocksSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` on normal lines, `kNodeLayer3` in packet mode |
| `layer_group_prev_node` | `kNodeLayer4` on normal lines, `kNodeLayer3` in packet mode |
| `layer_group_next_node` | `kNodeLayer4` on normal lines, `kNodeLayer3` in packet mode |
| `required_padding_left` | `17` bytes on normal lines, `24` bytes in packet mode |
