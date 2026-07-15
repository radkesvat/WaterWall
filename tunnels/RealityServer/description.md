<!--
Documentation version: 107
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/RealityServer.mdx, and both files must keep the same documentation version.
-->

# RealityServer

`RealityServer` implements Reality v2. It starts each connection as a visitor TCP bridge, passively extracts the real ClientHello and final ServerHello binding, and only then tests client-to-server application records with fresh per-connection session keys. If a v2 record authenticates, it closes the visitor branch and switches the same Waterwall line to the normal `next` chain.

Typical placement:

- `TcpListener -> RealityServer -> protected-chain`
- `RealityServer.settings.destination` points to the visitor target, usually a `TcpConnector` for the real domain.

## Settings

- `destination` (string, required): node name for normal visitor traffic
- `password` (string, required): shared Reality secret
- `algorithm` / `method` (string, optional): `chacha20-poly1305` (default) or `aes-gcm`
- `salt` (string, optional): key derivation salt, default `waterwall-reality`
- `kdf-iterations` (number, optional): key derivation rounds, default `12000`
- `max-frame-size` (number, optional): maximum plaintext per Reality record, default `16356`
- `sniffing-attempts` (number, optional): TLS application records to try before treating the peer as a visitor, default `8`

## Behavior

The server does not terminate TLS. Its bounded streaming parser observes fragmented TLS records and handshake messages without delaying their normal forwarding, recognizes TLS 1.3 HelloRetryRequest, and waits for the final ServerHello. Malformed or unsupported handshakes switch to ordinary visitor behavior. Before the TLS binding and directional session keys are ready, application-data-looking records are visitor traffic and are never tried with the password-derived root key.

Non-TLS record headers are treated as visitor traffic as soon as the header is available. TLS application records that fail v2 authentication are also forwarded while sniffing remains pending. A successful record is not forwarded to the visitor target; the destination branch is finished, the authorized `next` chain is initialized, and decrypted payload is forwarded upstream.

After authorization, upstream traffic must be the exact next client-to-server record and downstream protected payload uses the independent server-to-client key, IV, and sequence. Duplicate, deleted, reordered, reflected, and cross-connection records fail; counters close before wrap.

The visible 12-byte prefix remains random cover data and part of the authenticated context. It is not the AEAD nonce; the nonce is derived from the directional session IV and implicit sequence number. There is no automatic fallback to the legacy static-key format.

## Compatibility

Reality v2 is wire-incompatible with v1 and requires a coordinated client/server upgrade. The password-derived value is only a root key for per-TLS-session derivation. No persistent replay database is needed.

## Example

```json
{
  "name": "reality-server",
  "type": "RealityServer",
  "settings": {
    "destination": "visitor-site",
    "password": "replace-with-a-strong-secret",
    "algorithm": "chacha20-poly1305",
    "sniffing-attempts": 8
  },
  "next": "protected-chain"
}
```
