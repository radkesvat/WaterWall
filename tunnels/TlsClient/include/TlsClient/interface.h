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
WW_EXPORT void      tlsclientTunnelEnableHandshakeTakeover(tunnel_t *t);
WW_EXPORT bool      tlsclientTunnelIsHandshakeCompleted(tunnel_t *t, line_t *l);
WW_EXPORT bool      tlsclientTunnelGetHandshakeBinding(tunnel_t *t, line_t *l,
                                                       tlsclient_handshake_binding_t *binding);
/* TLS 1.2-only immediate takeover. TLS 1.3 callers must use the phased APIs below. */
WW_EXPORT bool      tlsclientTunnelDeinitAfterHandshake(tunnel_t *t, line_t *l, sbuf_t **pending_raw);
/*
 * Enters TLS 1.3 drain mode while retaining BoringSSL. All bytes accumulated
 * after the handshake-completing record are returned once through
 * |pending_raw|; the caller owns the returned buffer.
 */
WW_EXPORT bool      tlsclientTunnelBeginTakeoverDrain(tunnel_t *t, line_t *l, sbuf_t **pending_raw);
/*
 * Takes ownership of one complete raw TLS record on every return path,
 * discards cover plaintext, and synchronously forwards generated TLS protocol
 * output. Close/Fatal also performs TlsClient's silent direct-close sequence.
 */
WW_EXPORT tlsclient_post_handshake_result_t
tlsclientTunnelConsumePostHandshakeRecord(tunnel_t *t, line_t *l, sbuf_t *record);
/* Releases retained TLS 1.3 state and enters final raw passthrough. */
WW_EXPORT bool tlsclientTunnelCompleteTakeover(tunnel_t *t, line_t *l);
