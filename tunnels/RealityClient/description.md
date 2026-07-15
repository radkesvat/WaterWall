<!--
Documentation version: 107
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/RealityClient.mdx, and both files must keep the same documentation version.
-->

# RealityClient

`RealityClient` implements Reality v2. It performs a real client TLS handshake through an internal `TlsClient`, derives fresh directional session keys from that handshake, then takes over the raw connection and sends authenticated payload inside TLS-like application records.

Typical placement:

- `TcpListener -> RealityClient -> TcpConnector`

The configured `next` node is the transport to the Reality server. The client still needs TLS settings such as `sni` because the first phase is a real TLS handshake with the visitor domain through the server.

## Settings

- `sni` (string, required): passed to the internal `TlsClient`
- `verify` (boolean, optional): passed to the internal `TlsClient`, default `true`
- `ech-sni-trick` (string, optional): passed to the internal `TlsClient`
- `x25519mlkem768` (boolean, optional): passed to the internal `TlsClient`
- `password` (string, required): shared Reality secret
- `algorithm` / `method` (string, optional): `chacha20-poly1305` (default) or `aes-gcm`
- `salt` (string, optional): key derivation salt, default `waterwall-reality`
- `kdf-iterations` (number, optional): key derivation rounds, default `12000`
- `max-frame-size` (number, optional): maximum plaintext per Reality record, default `16356`

## Behavior

On upstream `Init`, `RealityClient` initializes its own line state and forwards `Init` into the internal `TlsClient`. When the TLS handshake completes, it captures the negotiated TLS version, cipher suite, client random, and server random while the SSL object is still available. It then deinitializes the internal TLS line and derives independent client-to-server and server-to-client keys and IVs from the captured values and password-derived root key.

From takeover onward, upstream payload is AEAD-encrypted and framed as TLS application-data records; downstream records are authenticated, decrypted, and forwarded as cleartext. Each direction accepts only its next implicit 64-bit sequence number. Duplicate, deleted, reordered, reflected, or cross-connection records fail authentication and close an authorized line. Counters never wrap.

The visible 12-byte field after the TLS header is random authenticated cover data, not the AEAD nonce. The nonce is derived from the directional IV and implicit sequence number. The node still advertises 17 bytes of left padding.

## Compatibility

Reality v2 is wire-incompatible with the previous static-key format. Upgrade `RealityClient` and `RealityServer` together. There is no automatic v1 fallback after v2 authentication fails. Changing the shared password invalidates future sessions; no server-side replay database is required.

## Example

```json
{
  "name": "reality-client",
  "type": "RealityClient",
  "settings": {
    "sni": "www.example.com",
    "verify": true,
    "password": "replace-with-a-strong-secret",
    "algorithm": "chacha20-poly1305"
  },
  "next": "server-tcp"
}
```
