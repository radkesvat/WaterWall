#pragma once
#include "wwapi.h"

typedef struct tlsclient_handshake_binding_s
{
    uint8_t  client_random[32];
    uint8_t  server_random[32];
    uint64_t next_read_sequence;
    uint64_t next_write_sequence;
    uint16_t tls_version;
    uint16_t cipher_suite;
    bool     tls12_sequences_valid;
} tlsclient_handshake_binding_t;

typedef enum tlsclient_post_handshake_result_e
{
    kTlsClientPostHandshakeNeedMore = 0,
    kTlsClientPostHandshakeClose,
    kTlsClientPostHandshakeFatal,
} tlsclient_post_handshake_result_t;

WW_EXPORT node_t    nodeTlsClientGet(void);
WW_EXPORT tunnel_t *tlsclientTunnelCreate(node_t *node);
/* Internal binding/takeover helpers require non-null tunnel/line arguments and required
 * outputs. Refusal reports protocol/state or operational failure, not invalid
 * pointers. Optional arguments are documented on their individual functions. */
/* Internal owner registration. Called once at the validated handshake record
 * boundary, separately from transport Est. The callback must begin/complete
 * takeover or close the exact line. The owner remains alive with this tunnel. */
typedef void (*tlsclient_handshake_ready_fn)(tunnel_t *owner, line_t *line);
WW_EXPORT bool tlsclientTunnelEnableHandshakeTakeover(tunnel_t *t, tunnel_t *owner,
                                                      tlsclient_handshake_ready_fn handshake_ready);
WW_EXPORT bool tlsclientTunnelIsHandshakeCompleted(tunnel_t *t, line_t *l);
WW_EXPORT bool tlsclientTunnelGetHandshakeBinding(tunnel_t *t, line_t *l, tlsclient_handshake_binding_t *binding);
/*
 * Generate a ClientHello using this tunnel's configured fingerprint, ALPN, and
 * ECH GREASE settings. Hostname bytes need not be NUL-terminated and must not
 * contain an embedded NUL. The caller line must belong to the current ordinary
 * worker. The caller owns the returned buffer and must return it through that
 * line's buffer pool; NULL reports validation, worker-ownership, or generation
 * failure.
 */
WW_EXPORT sbuf_t *tlsclientTunnelGenerateClientHello(tunnel_t *t, line_t *caller_line, const uint8_t *hostname,
                                                     uint32_t hostname_length);
/* TLS 1.2-only immediate takeover. pending_raw may be NULL when the caller does
 * not request trailing bytes. TLS 1.3 callers must use the phased APIs below. */
WW_EXPORT bool tlsclientTunnelDeinitAfterHandshake(tunnel_t *t, line_t *l, sbuf_t **pending_raw);
/*
 * Enters TLS 1.3 drain mode while retaining BoringSSL. All bytes accumulated
 * after the handshake-completing record are returned once through
 * |pending_raw|; the caller owns the returned buffer.
 */
WW_EXPORT bool tlsclientTunnelBeginTakeoverDrain(tunnel_t *t, line_t *l, sbuf_t **pending_raw);
/*
 * Takes ownership of one complete raw TLS record on every return path,
 * discards cover plaintext, and synchronously forwards generated TLS protocol
 * output. Close/Fatal also performs TlsClient's silent direct-close sequence.
 */
WW_EXPORT tlsclient_post_handshake_result_t tlsclientTunnelConsumePostHandshakeRecord(tunnel_t *t, line_t *l,
                                                                                      sbuf_t *record);
/* Releases retained TLS 1.3 state and enters final raw passthrough. */
WW_EXPORT bool tlsclientTunnelCompleteTakeover(tunnel_t *t, line_t *l);
