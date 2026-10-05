<!--
Documentation version: 158
Sync note: Any change to this file must also be applied to WaterWall/WaterWall-Docs/docs/02-noderefs/TlsClient.mdx and WaterWall/WaterWall-Docs/i18n/fa/docusaurus-plugin-content-docs/current/02-noderefs/TlsClient.mdx, and all files must keep the same documentation version.
-->

# TlsClient Node

`TlsClient` is a client-side TLS wrapper built on the bundled BoringSSL code in this repository.

It takes cleartext payload from the previous tunnel, encrypts it into TLS records for the next tunnel, and decrypts downstream TLS records back into cleartext.

This node is meant for the client side of a chain, usually between an application protocol tunnel and a transport adapter such as `TcpConnector`.

This node does a real Tls hadshake and mimics chorme behaviour, verified with JA4 hash and built with help of wireshark and inspecting chromes behaviour. it uses the exact libraries used in google chrome to do this (BoringSSl, LibBrotli)


## What It Does

- Creates a client-side TLS session for each Waterwall line.
- Sends a TLS ClientHello during upstream `Init`.
- Encrypts upstream payload with `SSL_write()`.
- Decrypts downstream payload with `SSL_read()`.
- Buffers application payload until the TLS handshake completes.
- Verifies peer certificates using a built-in CA bundle by default.

## Typical Placement

A common layout is:

- some cleartext-producing tunnel
- `TlsClient`
- `TcpConnector`

Example:

- `HttpClient -> TlsClient -> TcpConnector`

That arrangement lets:

- `HttpClient` produce plain HTTP
- `TlsClient` protect it with TLS
- `TcpConnector` carry the encrypted bytes to the remote server

## Configuration Example

```json
{
  "name": "tls-client",
  "type": "TlsClient",
  "settings": {
    "sni": "example.com",
    "alpns": ["http/1.1"],
    "verify": true,
    "x25519mlkem768": true
  },
  "next": "tcp-connector"
}
```

## Required JSON Fields

### Top-level fields

- `name` `(string)`
  A user-chosen name for this node.

- `type` `(string)`
  Must be exactly `"TlsClient"`.

### `settings`

- `sni` `(string)`
  Required TLS server name indication.

  The value must contain between 1 and 255 bytes.

## Optional `settings` Fields

- `alpns` `(array of strings, default: ["h2", "http/1.1"])`
  Ordered ALPN protocol offer. The order written in JSON is preserved in the TLS ClientHello.

  Each protocol name must contain between 1 and 255 bytes, duplicate names are rejected, and the encoded list may not
  exceed 65,533 bytes. An empty array disables ALPN. The singular key `alpn` is not supported.

- `verify` `(boolean, default: true)`
  Controls whether BoringSSL verifies the peer certificate chain.

  When this is left enabled:

  - peer verification stays enabled
  - the built-in CA bundle from `utils/cacert.h` is loaded into the TLS context

  When this is disabled:

  - `TlsClient` still performs a real TLS handshake
  - BoringSSL peer verification is disabled for that tunnel instance
  - certificate chain errors no longer fail the handshake at the TLS layer

- `x25519mlkem768` `(boolean, default: true)`
  Controls whether `TlsClient` advertises the `X25519MLKEM768` hybrid post-quantum group.
  It controls key agreement only; setting it to `false` leaves the advertised signature algorithms, including ML-DSA, enabled.

  When this is left enabled, the tunnel stays closer to current Chrome TLS behavior.

  If you disable it:

  - the generated ClientHello becomes smaller
  - the tunnel no longer mimics Chrome as closely
  - you lose the Chrome-like `X25519MLKEM768` key share behavior

- `verbose` `(boolean, default: false)`
  Enables extra TLS state logging.

- `fragment` `(object, default: absent)`
  Inserts a private StreamFragmenter after TLS encoding; see TLS Stream Fragmentation below.

- `tls13-record-shaping` `(object, default: absent/disabled)`
  Enables the experimental sender-side TLS 1.3 record shaping described below.

Optional defaults apply only when their keys are absent. If `alpns` is absent, the Chrome-like default
`["h2", "http/1.1"]` is used. If `verify`, `x25519mlkem768`, or `verbose` is present, it must be a JSON boolean. Any other
type is a startup error.

## TLS Stream Fragmentation

An optional `fragment` object creates a private StreamFragmenter immediately after
TlsClient:

```text
previous -> TlsClient -> internal StreamFragmenter -> configured next
```

```json
"fragment": {
  "mode": "counter",
  "count": 1,
  "tls-hello-fragment": true,
  "tls-hello-timeout-ms": 1000,
  "cuts": [[250, 2, 100], [300, 5, 100]]
}
```

The object uses StreamFragmenter's settings and strict validation: `mode`,
`count` or `duration-ms`, `cuts`, optional `bypass_chance`, `wait-for-est`,
`tls-hello-fragment`, and `tls-hello-timeout-ms`. Omit `fragment` to omit the
helper. A present value must be a valid object; `null`, booleans, empty objects,
and duplicate keys are rejected.

With `tls-hello-fragment` absent or false, cuts split selected outgoing TLS
Payload callbacks at raw byte offsets. Every TLS byte, including record headers,
stays unchanged. TlsClient's complete initial TLS flight enters the helper as
one Payload, so `count: 1` selects that first flight in this mode.

With `tls-hello-fragment: true`, cuts count ClientHello handshake bytes, including
the four-byte handshake header and excluding each five-byte TLS record header.
Only the initial ClientHello is eligible. Selected cuts create valid, smaller
handshake records while preserving the complete handshake message, original
record boundaries, and record versions. Record headers change; encrypted records
and downstream TLS input do not. The complete message is capped at 64 KiB.
Non-TLS or unsupported framing, an oversized hello, bypass, and an incomplete
hello reaching `tls-hello-timeout-ms` pass the original wire bytes unchanged and
end detection for that line. The timeout starts on the first eligible non-empty
input, including time waiting for Est or Resume. Finish discards an incomplete
candidate instead of replaying it. The option does not infer SNI-relative cuts
or provide independent TLS and TCP cut profiles.

`wait-for-est` defaults to true: output waits until transport Est has been
forwarded, then fragment delays start. The TLS assembly deadline may run before
Est or while paused; a completed rewrite is no longer subject to that deadline.
Timed eligibility starts at the first Est by default. Explicit `wait-for-est:
false` permits output scheduling before Est. Later buffering may combine writes
or change spacing on the wire; neither mode promises TCP packet boundaries.

The helper borrows the same line and uses its own bounded FIFO: 8 MiB logical
bytes, 8 MiB capacity charge, and 1,024 jobs. Pause, reentry, Finish, and
shutdown use StreamFragmenter's normal ordering and cleanup. This budget is
separate from TLS plaintext and ciphertext-shaping storage. TlsClient still
blocks whole-chain splice eligibility.

`tls13-record-shaping` can be used with `fragment`: its record padding and
delays run first, followed by StreamFragmenter. The raw ClientHello-generation
API returns its normal buffer without entering this per-line helper.

## Experimental TLS 1.3 Record Shaping

`tls13-record-shaping` optionally pads and delays the first locally sent TLS 1.3 application records. It is disabled
when absent. It never changes received ciphertext, handshake records, alerts, empty application records, fallback bytes,
or TLS 1.2 records. Configure the local `TlsClient` and remote `TlsServer` separately when both sending directions should
be shaped.

Custom form:

```json
"tls13-record-shaping": {
  "scope": {"first-application-records": 8},
  "outcomes": [
    {
      "probability": 50,
      "padding-bytes": [100, 200],
      "delay": {"probability": 75, "ms": [10, 20]}
    },
    {"probability": 10, "padding-bytes": [400, 600]}
  ]
}
```

`padding-bytes` and `delay.ms` accept either an integer or an inclusive `[minimum, maximum]` integer range. There may be
1 through 16 outcomes; `first-application-records` is 1 through 1024, padding is 1 through 4096 bytes, and delay is 0
through 1000 milliseconds. Outcome probabilities are cumulative, mutually exclusive percentages whose sum may not exceed
100. One roll selects at most one outcome; the unused percentage is an unchanged record. An outcome's delay probability
is rolled only after that outcome is selected. Unknown keys and non-integer or out-of-range values are startup errors.
Every eligible record consumes one scope position even when its roll selects no outcome.

Only the custom `scope` plus `outcomes` form is currently accepted. The `profile` key is rejected until representative
capture, overhead, connection-success, and classifier measurements justify publishing a versioned preset.

Padding is standard zero-valued TLS 1.3 `TLSInnerPlaintext` padding and adds the selected number of bytes to ciphertext,
subject to the remaining legal TLS record capacity. Delay starts after encryption and adds up to the selected latency.
Records stay in wire order with `release_at = max(now + delay, previous_release_at)`. Queued ciphertext is bounded to 8
MiB per line, with producer backpressure at 6 MiB and release at 3 MiB. Pause and Resume propagation follows the
current wire state: if draining during Resume re-enters with another wire Pause, the stale Resume is suppressed until a
later wire Resume. If the cleartext side finishes, the timer is canceled and queued client ciphertext is synchronously
released in FIFO order while the wire remains writable. If the wire is paused, any remainder is discarded; local state
and upstream `Finish` are completed before the callback returns.

After the configured application-record scope is consumed, the current shaping queue first drains completely so no later
TLS record can overtake delayed ciphertext. While that ordering barrier is active, the cleartext producer remains paused
even below the normal low watermark. At an empty queue and complete write-BIO boundary, the timer and per-line shaping
queue are released; later TLS output is forwarded directly without record parsing or shaping metadata. Ordinary wire
Pause still applies in this direct phase. The 8 MiB limit and 6/3 MiB watermarks therefore bound only the finite active
shaping window.

During this synchronous final drain, downstream Payload and Est are discarded, while Pause and Resume only update the
local wire-paused state; none of those callbacks is forwarded toward the finished cleartext owner. A wire-side finish
cancels and discards queued output and is propagated only toward cleartext. Timer allocation failure drains immediately
in order.

Delay shaping is rejected for internal handshake-takeover users such as `RealityClient`, because raw takeover cannot
inherit a pending delayed TLS record. Padding-only shaping remains compatible when the takeover boundary is empty.

Record shaping can make early sizes and timings less deterministic, but it cannot remove an inner handshake round trip,
make a burst smaller, or hide every direction and timing feature. Combine it with `MuxClient`/`MuxServer` when
multiplexing fits the deployment.

Internal users can enable handshake takeover mode. TLS 1.2 may still release immediately after the handshake, while TLS
1.3 uses the phased drain API described below so post-handshake records are processed before the line becomes raw
pass-through.

## Tunnel API

`TlsClient` exposes an API that can generate a raw TLS ClientHello buffer.

Accepted request format:

- `generateTlsHello:<sni>`
  Generates a ClientHello using the tunnel's configured behavior.

Important note:

- the API SNI must contain between 1 and 255 bytes
- the API follows the tunnel's configured `settings.alpns` order
- the API follows the tunnel's `settings.x25519mlkem768` value
- if that setting is disabled, the generated ClientHello is smaller but less Chrome-like

### Internal handshake takeover API

This path is used by internal owners such as `RealityClient`; it has no JSON setting:

- `tlsclientTunnelEnableHandshakeTakeover()` enables record-bounded takeover input.
- `tlsclientTunnelGetHandshakeBinding()` captures the negotiated binding while BoringSSL is retained.
- `tlsclientTunnelDeinitAfterHandshake()` performs the TLS 1.2-only immediate release.
- `tlsclientTunnelBeginTakeoverDrain()` starts TLS 1.3 external post-handshake dispatch and returns accumulated raw bytes.
- `tlsclientTunnelConsumePostHandshakeRecord()` consumes one complete TLS 1.3 record and flushes generated protocol output.
- `tlsclientTunnelCompleteTakeover()` releases retained TLS state and enters raw pass-through.

TLS 1.3 callers must not use the immediate TLS 1.2 release API.

## Detailed Behavior

### Startup and handshake flow

On upstream `Init`, `TlsClient`:

- creates per-line SSL state
- creates owned-buffer ciphertext BIOs backed by the line's buffer pool
- switches the SSL object into client mode
- sets the configured SNI
- forwards upstream `Init` to the next tunnel
- immediately calls `SSL_connect()` to generate the first handshake flight

Handshake output is taken from the write BIO as owned buffers and sent upstream after the SSL call returns.
The initial ClientHello flight is assembled into one buffer for the next tunnel.

This is why `TlsClient` works well in chains such as:

- `SomeTunnel -> TlsClient -> TcpConnector`

The connector can buffer the ClientHello until the actual socket connect completes.

### `Est` versus TLS-ready state

In Waterwall terms, downstream `Est` still represents the underlying transport becoming established.

Current implementation detail:

- `tlsclientTunnelDownStreamEst()` forwards transport `Est` once, including for the internal Reality takeover path
- TLS handshake completion uses a separate owner callback registered with `tlsclientTunnelEnableHandshakeTakeover()`;
  it runs once at the validated TLS record boundary and never emits another `Est`

So `Est` does not mean application data is already safe to send immediately on the wire as cleartext.
Payload is valid after adjacent Init, including before transport Est. Plaintext waiting for TLS readiness or older
reentrant output is bounded to 2 MiB and 1,024 buffers, including the active retained head. Equality is accepted;
transactional admission refusal closes the borrowed line through its owner and frees queued data. Handshake completion
and Resume drain this FIFO as independent producers: wire Pause stops the drain before the next plaintext record.
New input cannot overtake an older retained head. The separate ciphertext-shaping budgets are unchanged.
The first retained plaintext buffer is published before notifying the cleartext source with Pause. Protocol/order wait,
wire pressure and ciphertext-shaping pressure share one source notification latch. Resume is emitted only after TLS is
ready, the older plaintext FIFO is empty and wire/shaping pressure has cleared. This source pressure does not pause
incoming TLS handshake records.

### Upstream payload behavior

Before handshake completion:

- upstream plaintext joins the bounded protocol-wait FIFO

After handshake completion:

- queued payload is flushed through `SSL_write()` in FIFO order while wire output is not paused
- new upstream payload is encrypted immediately
- resulting TLS records are taken from the write BIO as owned buffers and forwarded upstream after the SSL call returns
- a debug log records the negotiated TLS version, cipher, and ALPN value; it uses `alpn=<none>` when no protocol was
  negotiated

For eligible nonempty TLS 1.2/1.3 application writes after the handshake, a local BoringSSL hook reserves space in
the output BIO and encrypts directly into its pooled buffer. Pending control flights, write retries and declined
reservations use the ordinary copying path. The hook preserves record padding and ordering; it has no JSON setting.
Port `RadkesvatPatches/record_write_buffer_callbacks.patch` after the record-padding patch on every BoringSSL update.
The [BoringSSL update notes](my%20notes.txt) describe the API, symbol-prefix entry, ownership rules and required checks.

If `SSL_write()` or BIO flushing fails:

- line state is destroyed first
- upstream `Finish` is sent
- downstream `Finish` is sent

### Downstream payload behavior

Downstream payload is treated as encrypted TLS record data from the network.

The tunnel:

- transfers ownership of encrypted input buffers to the read BIO
- advances the handshake if the session is not finished yet
- flushes any handshake or protocol bytes generated by BoringSSL back upstream
- reads decrypted application bytes with `SSL_read()`
- forwards those cleartext bytes downstream toward the previous tunnel

Handshake-takeover mode changes only this internal path. It accumulates and validates complete TLS records, feeds one
record at a time to `SSL_connect()`, and stops at the exact record that completes the handshake. It verifies that neither
the read BIO nor BoringSSL's internal TLS read buffer owns later ciphertext. For TLS 1.3, the owner can then retain the
SSL/BIO state, submit complete post-handshake records one at a time, discard any cover application plaintext, and flush
protocol output generated for messages such as `KeyUpdate`. Only the final completion call releases BoringSSL and enables
raw pass-through. Ordinary `TlsClient` lines continue using the existing streaming `SSL_read()`/`SSL_write()` path.

When the TLS peer sends `close_notify` or a fatal TLS error occurs, the tunnel destroys its line state and closes both Waterwall directions immediately.

### Close and shutdown policy

`TlsClient` uses direct transport close semantics. It does not call `SSL_shutdown()`, does not generate a TLS
`close_notify` during normal Waterwall `Finish`, and does not wait for a peer shutdown response.

This normal-close choice is intended to mimic the Chrome behavior targeted by this tunnel: when the user or application
closes the connection in this situation, Chrome closes the transport without first sending TLS `close_notify`. This is not
a claim that Chrome never sends `close_notify` in every TLS shutdown context.

The observable policy is:

- upstream normal `Finish`: free TLS state and forward `Finish` only to the next node
- downstream raw transport `Finish`: free TLS state and forward `Finish` only to the previous node
- peer `close_notify`: consume it, send no client `close_notify` response, and close both directions immediately
- fatal TLS, certificate, record, `SSL_write()`, or BIO failure: close every initialized direction immediately
- TLS 1.2 handshake takeover: release TLS state without closing the underlying line, then continue as raw pass-through
- TLS 1.3 handshake takeover: retain TLS state during authenticated handoff, process complete post-handshake records,
  then release it only when the owner completes takeover

There is no JSON setting for this policy. Peers that require a full TLS shutdown handshake may report the resulting EOF as
a truncated TLS shutdown; that is intentional for this client tunnel.

### SSL context behavior

The tunnel creates one `SSL_CTX` per worker thread at tunnel construction time.

Current SSL context configuration includes:

- peer verification enabled by default, or disabled when `settings.verify` is `false`
- minimum protocol version TLS 1.2
- maximum protocol version TLS 1.3
- session cache mode enabled for client sessions
- GREASE enabled
- extension permutation enabled
- configured signature algorithms
- configured supported groups list
- signed certificate timestamps enabled
- Brotli certificate decompression support

When verification is enabled, the tunnel also loads a built-in CA certificate bundle from `utils/cacert.h`.

### Chrome-like handshake shaping

The source code intentionally tries to make the handshake look Chrome-like.

That includes:

- a Chrome-like default ALPN list containing `h2` and `http/1.1`, unless `settings.alpns` overrides it
- ALPS support for `h2` when offered through ALPN, with empty client application settings
- OCSP stapling extension
- signed certificate timestamp extension
- certificate compression support with Brotli

The bundled BoringSSL tree also contains local patches used by this tunnel.

## Notes And Caveats

- `TlsClient` is a client-side tunnel, not a TLS server.
- `downstream Init` is disabled in the current implementation and aborts if called.
- The tunnel does not open sockets by itself. Pair it with a transport such as `TcpConnector`.
- `settings.alpns` changes a fingerprint-relevant part of the ClientHello; the default remains Chrome-like.
- `settings.verify` defaults to `true`; when disabled, certificate verification is skipped for that tunnel instance.
- `Est` reflects transport establishment, not TLS handshake completion.

## Advanced Details

This section is a programmer-facing summary of the concrete shaping work in `TlsClient` and its vendored BoringSSL copy.

### Baseline capture and fingerprint goal

The implementation work was driven by real Chrome captures and compared primarily against modern TLS fingerprints such as JA4.

- The practical target is Chrome-like behavior on the wire, not just using BoringSSL defaults.
- JA4 alignment matters more than JA3 for this tunnel because Chrome permutes extension order and JA3 is sensitive to that ordering.
- Matching JA3 exactly is not expected on every connection once extension permutation is enabled.

### Ordered ALPN advertisement and application-protocol responsibility

`settings.alpns` is encoded into the ClientHello in exactly the configured order. If the setting is absent, `TlsClient`
advertises the Chrome-like default `h2`, then `http/1.1`. `[]` disables ALPN entirely.

The list is an offer, not a guarantee that the first item will be used. The TLS server selects the negotiated protocol
from the offered values. `TlsClient` does not report that selected protocol to the previous WaterWall node, and it does
not switch or validate the previous node's application protocol. Matching the ALPN offer to the cleartext protocol
produced before `TlsClient` is therefore the user's responsibility.

This is especially important for `HttpClient -> TlsClient` chains:

- If `HttpClient` is configured for HTTP/1.1 WebSocket Upgrade, configure `TlsClient` with only
  `"alpns": ["http/1.1"]`.
- If the deployment uses WebSocket over HTTP/2, configure `HttpClient` for HTTP/2 so it uses the HTTP/2 CONNECT path,
  and configure `TlsClient` with only `"alpns": ["h2"]`.
- Offering both `h2` and `http/1.1` is valid, commonly used, and closer to Chrome's default ClientHello. When using that
  offer with a fixed preceding `HttpClient`, the user must know which protocol the target server will select and
  configure `HttpClient` for that version. If the target's choice is unknown or can vary, offer only the protocol that
  matches `HttpClient`.

**Cloudflare caution (as of July 2026):** For ordinary HTTPS through a Cloudflare-proxied hostname with HTTP/2 enabled,
Cloudflare selects `h2` when it is offered. It is therefore reasonable to keep the Chrome-like
`"alpns": ["h2", "http/1.1"]` offer and configure the preceding `HttpClient` for HTTP/2. This does not apply to
WebSocket: Cloudflare's currently documented proxied WebSocket behavior does not support HTTP/2 WebSocket extended
`CONNECT` (RFC 8441). For Cloudflare WebSocket, force HTTP/1.1 WebSocket Upgrade by configuring this node with only
`"alpns": ["http/1.1"]` and configuring `HttpClient` for HTTP/1.1. Re-check Cloudflare's current capabilities before
depending on either behavior, because provider settings and support can change.

Multiple ALPN offers are appropriate when the target server's selection is known and stable. They are not automatic
application-protocol discovery: the preceding node must already be configured for the protocol the server will select.

At handshake completion, `TlsClient` writes the selected value to the debug log as `alpn="..."`, or `alpn=<none>` when
the handshake negotiated no ALPN. This is diagnostic output only; it does not communicate the selection to the preceding
application tunnel.

### TLS version and extension behavior

The SSL context is configured to stay in the same protocol band this tunnel was designed for.

- minimum protocol version is TLS 1.2
- maximum protocol version is TLS 1.3
- GREASE is enabled
- TLS extension permutation is enabled
- ECH grease is enabled on each `SSL` object
- OCSP stapling and signed certificate timestamps are enabled

### Cipher suite ordering patch

The bundled BoringSSL client handshake logic is patched so the advertised cipher suites follow a Chrome-style fixed order instead of BoringSSL's default selection logic.

- TLS 1.3 cipher order is forced
- TLS 1.2 cipher order is forced
- this change lives in the local `handshake_client.cc` patch
- the purpose is wire-level ordering control, not cryptographic behavior changes

### Supported groups and signature algorithms

The context configures supported groups explicitly. Ignoring randomized GREASE entries, the default list is:

```text
X25519MLKEM768:X25519:P-256:P-384
```

The initial TLS 1.3 `key_share` offer contains `X25519MLKEM768` followed by `X25519`, in addition to GREASE.
The default supported-group order matches the Chrome 154 reference; this does not imply that the complete handshake
matches Chrome.

The explicit `settings.x25519mlkem768: false` opt-out remains supported. It uses:

```text
X25519:P-256:P-384
```

In that mode, `X25519` is the only non-GREASE initial key share.

The `signature_algorithms` offer starts with a randomized GREASE value, followed by these algorithms in the order
captured from Chrome 154:

```text
ML-DSA-44
ML-DSA-65
ML-DSA-87
ecdsa_secp256r1_sha256
rsa_pss_rsae_sha256
rsa_pkcs1_sha256
ecdsa_secp384r1_sha384
rsa_pss_rsae_sha384
rsa_pkcs1_sha384
rsa_pss_rsae_sha512
rsa_pkcs1_sha512
```

ML-DSA signature schemes are independent of the `x25519mlkem768` key-agreement setting. Ordinary TLS connections and
the raw ClientHello generator use the same context configuration for this offer. Matching these fields does not
establish complete Chrome fingerprint equivalence.

### Certificate compression support

Chrome supports Brotli certificate decompression, so this tunnel does too.

- the repo includes a local Brotli decompressor object for certificate decompression
- `SSL_CTX_add_cert_compression_alg` is used with Brotli decompression only
- compression is not offered for local certificate output, matching the intended client-side behavior here

### ALPS handling

`TlsClient` registers ALPS only for `h2`, and only when `h2` is in `settings.alpns`. The registered client application
settings are empty, matching Chrome's HTTP/2 registration. `http/1.1` and custom ALPN protocols have no ALPS registration;
when `h2` is absent, the ClientHello has no ALPS extension. ALPS uses extension codepoint `17613` (`0x44cd`).

`SSL_add_application_settings` takes the protocol name and its application settings as separate arguments. The bytes
`02 68 32` encode the length-prefixed protocol name `h2`; they are not application settings. BoringSSL serializes the
ClientHello ALPS protocol list as `00 03 02 68 32`. If the server negotiates ALPS for `h2`, the client sends an empty
application-settings value in the encrypted handshake. Do not substitute a protocol-name encoding or an HTTP/2
`SETTINGS` frame for that empty value.

`TlsClient` does not parse, apply, or forward received server application settings to the preceding node. Its ALPS
configuration shapes the TLS exchange visible to a passive observer; it does not implement Chrome's HTTP/2 response
to server settings or make the connection indistinguishable from Chrome to the server.

### Trust Anchor IDs

`TlsClient` advertises the 28 Trust Anchor IDs captured from Chrome `154.0.8037.97`, using Chrome Root Store 39.
BoringSSL encodes them in extension `0xca34`. The IDs identify 13 roots already present in WaterWall's built-in CA
bundle and 15 intermediate certificates. Their source paths and certificate fingerprints are recorded in
`tests/unittests/fixtures/tlsclient_chrome/trust_anchors.json`.

With verification enabled, each SSL context owns a cache of those 15 intermediates. When the server reports a matching
Trust Anchor ID, the verifier adds the cached certificates as untrusted chain-building candidates so the server can
omit them from its certificate message. They do not become trusted roots. Normal certificate signatures, validity,
hostname, purpose, path-length and name constraints still apply, and the chain must reach an existing trusted root.
The ID advertisement also remains present with `verify: false`; that setting still disables server authentication.

The ID list and intermediate cache are a paired, pinned profile. Update them together against their source mappings
and the verifier's supported roots.

### ClientHello Reference Comparison

`waterwall.tlsclient_alpn_unit` compares the complete initial ClientHello with the checked-in capture of Google Chrome
`154.0.8037.97` on Linux x86-64 with AES hardware. The reference case uses a fresh TCP connection, SNI
`tls.integration.test`, default ALPN and groups, and ordinary ECH GREASE without custom overrides or fragmentation.

The comparison covers record and handshake framing, versions, cipher order, compression, the complete extension set,
and extension payloads, including Trust Anchor IDs. It normalizes random bytes, GREASE values and interior extension
permutation, while preserving the leading empty and trailing one-byte GREASE extension positions and payloads.
Key-share lengths and the permitted ECH GREASE framing and payload sizes are also checked. This is an initial-ClientHello
comparison for that profile; it does not establish resumption, real ECH, later record sizes or timing, or application
behavior matching Chrome.

### CA verification and session behavior

The tunnel is still a real TLS client, not just a fingerprint shaper.

- peer verification is enabled by default and can be disabled with `settings.verify`
- when verification is enabled, CA roots are loaded from the built-in bundle in `utils/cacert.h`
- client session caching is enabled
- application data is buffered until the TLS handshake completes

### Vendored BoringSSL integration

The bundled source is pinned to BoringSSL revision `ac39ea6853833c1f18fd23614091d11855e71752`, selected by Chromium
`154.0.8037.97`. This dependency pin does not make every WaterWall TLS setting or application behavior match Chrome.
The build consumes static `crypto` and `ssl` libraries with `BUILD_SHARED_LIBS`, `BUILD_TOOL`, `BUILD_TESTING`, and
`INSTALL_ENABLED` disabled. Local CMake changes preserve those embedding controls and the MSVC secure-zero warning
exception. Upstream already excludes the SysV-only Fiat P-256 assembly from Windows.

Local changes also preserve fixed cipher ordering, ECH GREASE overrides, sender-side TLS 1.3 record padding, and direct
record output buffers. Port the padding patch before the direct-output patch; recheck their ownership and record-ordering
contracts against the new library. The [BoringSSL update notes](my%20notes.txt) contain the patch and validation checklist.

## Prefixing BoringSSL Beside OpenSSL

WaterWall links ordinary OpenSSL and BoringSSL into the same executable. BoringSSL is compiled with
`BORINGSSL_PREFIX=WW_BSSL`, so its public symbols, internal C++ namespace, and assembly helpers remain separate from
OpenSSL. Every BoringSSL consumer must use the same prefix definition and the bundled BoringSSL include directory;
OpenSSL consumers use OpenSSL's own headers and objects. Never exchange SSL or BIO objects between the two libraries.

Upstream supplies the prefix mappings in these checked-in files:

- `boringssl/include/openssl/prefix_symbols.h` for public symbols
- `boringssl/include/openssl/prefix_symbols_internal_c.h` and `prefix_symbols_internal_S.h` for internal/assembly symbols
- `boringssl/gen/boringssl_prefix_symbols_internal_x86_win_asm.inc` and `boringssl_prefix_symbols_internal_x86_64_win_asm.inc`
  for Windows NASM

Normal builds consume those files directly and need neither Go nor Python for symbol prefixing. The build configuration
sets `BORINGSSL_PREFIX` before adding the dependency, and applies the same definition to `TlsClient`, `DecompressBrotli`,
and native tests that consume BoringSSL.

`RadkesvatPatches/prefix_symbols.patch` adds the four local SSL APIs to the public prefix header. Reapply that patch after
the API patches. When the declarations change, the public header can be regenerated from the BoringSSL source root
with upstream's tool:

```bash
go run ./util/pregenerate include/openssl/prefix_symbols.h
```

This optional regeneration step requires the Go version in BoringSSL's `go.mod` and Clang. Keep the public header and
its saved patch consistent. They must include both ECH override functions, `SSL_set_tls13_record_padding_callback`, and
`SSL_set_record_write_buffer_callbacks`. Preserve upstream's mappings for all supported architectures; a native x86
symbol scan alone cannot establish ARM or Windows coverage.

Validate the static archives for unprefixed BoringSSL definitions and link the complete WaterWall executable with its
OpenSSL dependency. Run the focused TLS, Reality, record-padding, and buffer-BIO regressions in Debug and Release, then
the production lanes required by the Developer Guide. Successful linking alone does not prove that a call bound to the
intended TLS library.

## Advanced: ECH SNI Trick

**Advanced, specialized behavior:** This feature is not part of ordinary TLS configuration or the normal responsibility
of `TlsClient`. Use it only when a deployment deliberately coordinates TLS ClientHello construction with compatible
packet-level manipulation.

The optional `ech-sni-trick` setting accepts a hostname string containing between 1 and 255 bytes:

```json
"ech-sni-trick": "example.net"
```

When configured, `TlsClient` creates a second, fake ClientHello using that hostname and embeds its bytes as the GREASE
`encrypted_client_hello` payload of the real outer ClientHello. The outer cleartext SNI remains `settings.sni`.

The embedded fake ClientHello uses the configured `alpns` list in the same order, but disables `x25519mlkem768` to keep
the payload smaller. This behavior is intended to coordinate with packet-side mechanisms such as `IpManipulator`'s
packet-splitting trick, keeping the ClientHello bytes hashed by BoringSSL consistent with the bytes placed on the wire.

The value must be a JSON string containing between 1 and 255 bytes; a value outside that range or another JSON type is a
startup error. The raw ClientHello generation API also applies this setting when it is configured.

## Node Metadata

Source-backed metadata:

This node explicitly disables splice for the entire chain through
`kNodeFlagBlocksSplice`, even if `kNodeFlagSupportsSplice` is also set.

| Property | Value |
| --- | --- |
| node flags | `kNodeFlagBlocksSplice` |
| `can_have_prev` | `true` |
| `can_have_next` | `true` |
| `layer_group` | `kNodeLayer4` |
| `layer_group_prev_node` | `kNodeLayer4` |
| `layer_group_next_node` | `kNodeLayer4` |
| `required_padding_left` | `0` bytes |

## Acknowledgements

WaterWall's fragmentation features draw inspiration from:

- **[GFW-knocker](https://github.com/GFW-knocker/gfw_resist_tls_proxy)** — for practical work on splitting TLS
  ClientHello traffic into smaller TCP stream writes with delays, which inspired our stream fragmentation approach.
- **[patterniha](https://github.com/XTLS/Xray-core/issues/4370)** — for explaining and exploring TLS record
  fragmentation and its distinction from TCP fragmentation, which informed our TLS ClientHello record fragmentation
  feature.

We thank both developers for sharing their work with the community.
