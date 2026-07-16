<!--
Documentation version: 112
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

## Behavior

On upstream `Init`, `RealityClient` initializes its own line state and forwards `Init` into the internal `TlsClient`. When the TLS handshake completes, it captures the negotiated TLS version, cipher suite, client random, server random, and (for TLS 1.2) the next BoringSSL read/write record sequences while the SSL object is still available. It selects a shared record profile before deinitializing the internal TLS line, then derives independent client-to-server and server-to-client keys and IVs from the captured values and password-derived root key. An unsupported negotiated suite aborts takeover instead of falling back to another record shape.

From takeover onward, upstream payload is AEAD-encrypted and framed as TLS application-data records; downstream records are authenticated, decrypted, and forwarded as cleartext. Each direction accepts only its next implicit 64-bit sequence number. Duplicate, deleted, reordered, reflected, or cross-connection records fail authentication and close an authorized line. Counters never wrap.

Shutdown is role-specific. A local upstream finish destroys Reality state and finishes only the wire side; it never synthesizes `close_notify`. An authenticated server `close_notify` is consumed without a response, then RealityClient immediately destroys its state and closes both still-open sides. It never waits for a later TCP FIN, so an authenticated peer cannot pin the connection open by withholding FIN. Authenticated record corruption detected locally is the client's only alert-producing path and emits at most one TLS-shaped fatal `bad_record_mac` before both sides close; a received fatal alert likewise closes both sides immediately without a response. A raw transport finish closes only the remaining local side. No setting controls this policy.

Reality automatically limits each application plaintext fragment to `16384` bytes and immediately splits larger WaterWall payload callbacks without buffering across callbacks. The visible takeover layout follows the negotiated cover TLS profile:

- TLS 1.3 uses `Reality-AEAD(payload | encrypted inner type 0x17) | 16-byte tag`, with no visible nonce or prefix. The body is `payload + 17` bytes and reaches `16401` bytes for a full fragment.
- TLS 1.2 ChaCha uses `Reality-AEAD(payload) | 16-byte tag`, with no visible nonce or prefix. The body reaches `16400` bytes.
- TLS 1.2 AES-GCM uses `8-byte explicit nonce | Reality ciphertext | 16-byte tag`; client records continue BoringSSL's captured TLS write sequence in big-endian form.
- TLS 1.2 AES-CBC uses `16-byte random explicit IV | block-aligned opaque body`. Its authenticated inner plaintext carries a two-byte payload length and zero filler so the public length matches the suite's TLS MAC and minimum-padding formula. Reality does not perform CBC encryption. Full-fragment GCM and CBC/SHA-1 bodies are `16408` and `16432` bytes.

Alert records match BoringSSL's public shutdown shapes: TLS 1.3 uses outer application data with a 19-byte body and encrypted inner alert type; TLS 1.2 GCM, CBC/SHA-1, and ChaCha use outer alert records with 26-, 48-, and 18-byte bodies respectively. Alert semantics are encrypted, and application data and alerts share one sequence in each direction. These are Reality-AEAD camouflage records, not genuine TLS closure or TLS-key alert encryption.

Visible prefixes are authenticated camouflage and are never used as Reality AEAD nonces. Reality nonces still come from the directional secret IV and independent Reality replay sequence. The node advertises the worst-case `21` bytes of left padding (`5 + 16`).

## Compatibility

This native-sized profile-aware format remains Reality v2 but replaces the earlier unpublished 12-byte-prefix application layout. Record kind and TLS version are authenticated in the associated data, so upgrade `RealityClient` and `RealityServer` together. There is no old-layout or v1 fallback after authentication fails. Supplying the obsolete `max-frame-size` setting is a startup error. Changing the shared password invalidates future sessions; no server-side replay database is required.

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
