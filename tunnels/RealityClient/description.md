# RealityClient

`RealityClient` performs a real client TLS handshake through an internal `TlsClient`, then takes over the raw connection and sends Reality-authenticated payload inside TLS-like application records.

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

On upstream `Init`, `RealityClient` initializes its own line state and forwards `Init` into the internal `TlsClient`. When the TLS handshake completes, the internal TLS line is deinitialized without closing the underlying connection. From that point, upstream payload is AEAD-encrypted and framed as TLS application-data records; downstream records are authenticated, decrypted, and forwarded as cleartext.

The node advertises enough left padding for the TLS record header and nonce prefix it prepends.

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
