<!--
Documentation version: 106
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/reality-server.mdx, and both files must keep the same documentation version.
-->

# RealityServer

`RealityServer` starts each connection as a visitor TCP bridge to a configured destination and sniffs client-to-server TLS application records. If a record authenticates as Reality traffic, it closes the visitor branch and switches the same Waterwall line to the normal `next` chain.

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

The server does not terminate TLS. It forwards handshake and ordinary visitor bytes to `destination`. Non-TLS record headers are treated as visitor traffic as soon as the header is available, so active plaintext or random probes are not held in the Reality sniff buffer. TLS application records that do not authenticate are also forwarded while sniffing remains active. A successful Reality record is not forwarded to the visitor target; instead the destination branch is finished, the authorized `next` chain is initialized, and decrypted payload is forwarded upstream.

After authorization, upstream traffic must be valid Reality records and downstream payload from the protected chain is encrypted into TLS-like application records.

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
