<!--
Documentation version: 113
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/RealityServer.mdx, and both files must keep the same documentation version.
-->

# RealityServer

`RealityServer` implements Reality v2. It starts each connection as a visitor TCP bridge, passively extracts the real ClientHello and final ServerHello binding, and only then tests client-to-server records with fresh per-connection session keys. TLS 1.3 requires an authenticated request/ack/confirm handoff before the visitor branch is closed and the same Waterwall line switches to the normal `next` chain. TLS 1.2 retains its immediate profile-aware authorization path.

Typical placement:

- `TcpListener -> RealityServer -> protected-chain`
- `RealityServer.settings.destination` points to the visitor target, usually a `TcpConnector` for the real domain.

## Settings

- `destination` (string, required): node name for normal visitor traffic
- `password` (string, required): shared Reality secret
- `algorithm` / `method` (string, optional): `chacha20-poly1305` (default) or `aes-gcm`
- `salt` (string, optional): key derivation salt, default `waterwall-reality`
- `kdf-iterations` (number, optional): key derivation rounds, default `12000`
- `sniffing-attempts` (number, optional): TLS application records to try before treating the peer as a visitor, default `8`
- `tls12-gcm-server-nonce-policy` (string, optional): `auto` (default), `sequence`, `counter`, or `random`

## Behavior

The server does not terminate TLS. Its bounded streaming parsers observe fragmented TLS records and handshake messages without delaying their normal forwarding, recognize TLS 1.3 HelloRetryRequest, and wait for the final ServerHello. For TLS 1.2 they independently track each direction's ChangeCipherSpec, protected-record sequence, and AES-GCM explicit nonce samples. Malformed or unsupported handshakes switch to ordinary visitor behavior. Before the TLS binding, record profile, and directional session keys are ready, application-data-looking records are visitor traffic and are never tried with the password-derived root key.

Non-TLS record headers are treated as visitor traffic as soon as the header is available. TLS application records that fail v2 authentication are also forwarded while sniffing remains pending. For TLS 1.3, only `HANDOFF_REQUEST` at client-to-server sequence `0` can leave Pending. The server consumes an authenticated request, tracks the already-forwarded destination stream through the end of its current complete TLS record, marks downstream cutoff, and sends `HANDOFF_ACK` at server-to-client sequence `0` only between records. Destination output after that cutoff is suppressed. Late genuine TLS protocol output from the client may still travel upstream to the destination until `HANDOFF_CONFIRM` authenticates at client-to-server sequence `1`; failed confirmation trials are bounded and never advance the sequence. Only confirmation closes the remaining destination direction and initializes protected `next`.

After authorization, upstream traffic must be the exact next client-to-server record and downstream protected payload uses the independent server-to-client key, IV, and sequence. Duplicate, deleted, reordered, reflected, and cross-connection records fail; counters close before wrap.

The server owns orderly Reality shutdown after authorization. A protected-side finish queues exactly one TLS-shaped `close_notify`, then immediately finishes the wire side without waiting for a reply. RealityClient consumes that record without replying and closes its TCP side immediately, even if a later server FIN is withheld. Normal clients close with raw transport FIN and do not send `close_notify`. Authorized corruption queues at most one fatal `bad_record_mac`; received fatal alerts are never answered. Raw wire finish cannot be answered and closes only the remaining protected path. Pending, Visitor, and either TLS 1.3 handoff phase never synthesize Reality alerts because the peer may still be interpreting the stream as cover TLS.

Reality automatically limits each application plaintext fragment to `16384` bytes and immediately splits larger WaterWall payload callbacks. The selected record profile matches the negotiated cover suite: TLS 1.3 has no visible prefix and encrypts `payload | inner type 0x17`; TLS 1.2 ChaCha has no visible prefix and encrypts only the payload; TLS 1.2 AES-GCM retains an eight-byte explicit nonce; and TLS 1.2 AES-CBC retains a random 16-byte explicit IV with a block-aligned body. Full-fragment bodies are `16401`, `16400`, `16408`, and `16432` bytes respectively. CBC sizing reproduces the suite's visible MAC/minimum-padding length without implementing CBC cryptography. Every visible prefix, profile ID, header, direction, session, and Reality sequence is authenticated.

TLS-shaped alerts follow BoringSSL's public layout: TLS 1.3 outer application data has a 19-byte body with encrypted inner alert type; TLS 1.2 GCM, CBC/SHA-1, and ChaCha outer alerts have 26-, 48-, and 18-byte bodies. Their two-byte semantic value is encrypted. Data and alerts use the same send/receive sequence, and record kind plus TLS version are included in associated data. These are Reality-AEAD camouflage records, not genuine TLS closure or TLS-key alert encryption.

TLS 1.3 `HANDOFF_REQUEST`, `HANDOFF_ACK`, and `HANDOFF_CONFIRM` use the same directional keys and strict Reality sequences as later data. Their versioned plaintext binds the expected control code and carries authenticated CSPRNG padding. The TLS body length is sampled uniformly from `22..1172` bytes (`3..1153` padding bytes), the range observed across the covered BoringSSL post-handshake paths. The controls have TLS 1.3 outer and inner application-data types, are never delivered to `next`, and have no JSON-configurable length. The visible request/ack/confirm timing remains a camouflage review consideration.

For downstream TLS 1.2 GCM, `auto` freezes `sequence` when observed cover nonces match record sequences, otherwise `counter` when at least two samples increment, and otherwise `random`. `sequence` emits the tracked next TLS record sequence, `counter` increments the last observed explicit nonce, and `random` emits fresh CSPRNG bytes. A manually selected `counter` requires an observed nonce. With one non-sequence sample, `auto` cannot distinguish random output from an arbitrary fixed-prefix counter; configure an explicit policy when the cover server's convention is known.

The visible TLS facade counter is separate from the secret Reality replay counter and is never used as the Reality AEAD nonce. Both nodes advertise `21` bytes of left padding for the largest CBC prefix. There is no fallback to the earlier unpublished 12-byte-prefix application layout or the legacy static-key format, and the obsolete `max-frame-size` setting is rejected at startup.

## Compatibility

The authenticated TLS 1.3 handoff requires a coordinated client/server upgrade from earlier unpublished v2 builds, including builds that switched immediately after the main TLS handshake. It remains wire-incompatible with v1. TLS 1.2 layouts and counters are unchanged. The password-derived value is only a root key for per-TLS-session derivation. No persistent replay database is needed.

## Example

```json
{
  "name": "reality-server",
  "type": "RealityServer",
  "settings": {
    "destination": "visitor-site",
    "password": "replace-with-a-strong-secret",
    "algorithm": "chacha20-poly1305",
    "tls12-gcm-server-nonce-policy": "auto",
    "sniffing-attempts": 8
  },
  "next": "protected-chain"
}
```
