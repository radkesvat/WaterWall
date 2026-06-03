# EncryptionClient

`EncryptionClient` applies AEAD encryption on upstream traffic and decrypts downstream traffic carried in TLS-like application-data records.

Recommended chain usage:

- Client side: `TcpListener -> EncryptionClient -> TcpConnector`
- Server side counterpart: `TcpListener -> EncryptionServer -> TcpConnector`

## Settings

- `algorithm` (string or number, optional): `chacha20-poly1305` (default) or `aes-gcm`
- `password` (string, required): shared secret used for key derivation
- `salt` (string, optional): key-derivation salt, default `waterwall-encryption`
- `kdf-iterations` (number, optional): key derivation rounds, default `12000`
- `max-frame-size` (number, optional): maximum plaintext frame size in bytes, default `16356`

## Example

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

## Wire Format

Encrypted payloads are sent as TLS-like application-data records:

- TLS record type `0x17`
- TLS version `0x0303`
- 16-bit record body length
- random nonce followed by AEAD ciphertext and tag

The selected algorithm is configured locally on both peers and is not exposed in the record header.
