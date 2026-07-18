#pragma once

#include "interface.h"
#include "wwapi.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

typedef struct tlsclient_tstate_s
{
    // settings
    char *alpn;
    char *sni;
    char *ech_grease_sni_override;
    bool  verify;
    bool  verbose;
    bool  x25519mlkem768_enabled;
    bool  handshake_takeover_enabled;

    // state
    SSL_CTX **threadlocal_ssl_contexts;
    SSL_CTX **threadlocal_ech_grease_inner_ssl_contexts;
} tlsclient_tstate_t;

typedef enum tlsclient_takeover_phase_e
{
    kTlsClientTakeoverHandshake = 0,
    kTlsClientTakeoverDrain,
    kTlsClientTakeoverPassthrough,
} tlsclient_takeover_phase_t;

typedef struct tlsclient_lstate_s
{
    SSL           *ssl;
    BIO           *rbio;
    BIO           *wbio;
    buffer_queue_t bq;
    buffer_stream_t takeover_stream;
    tlsclient_takeover_phase_t takeover_phase;
    bool           handshake_completed;
    bool           handshake_est_sent;
    bool           resources_released;
    bool           post_handshake_consume_in_progress;
} tlsclient_lstate_t;

enum
{
    kTunnelStateSize = sizeof(tlsclient_tstate_t),
    kLineStateSize   = sizeof(tlsclient_lstate_t)
};

enum sslstatus
{
    kSslstatusOk,
    kSslstatusWantIo,
    kSslstatusFail
};

enum tlsclient_record_e
{
    kTlsClientRecordHeaderSize = SSL3_RT_HEADER_LENGTH,
    kTlsClientMaxRecordBody    = SSL3_RT_MAX_ENCRYPTED_LENGTH,
};

static enum sslstatus getSslStatus(SSL *ssl, int n)
{
    switch (SSL_get_error(ssl, n))
    {
    case SSL_ERROR_NONE:
        return kSslstatusOk;
    case SSL_ERROR_WANT_WRITE:
    case SSL_ERROR_WANT_READ:
        return kSslstatusWantIo;
    case SSL_ERROR_ZERO_RETURN:
    case SSL_ERROR_SYSCALL:
    default:
        return kSslstatusFail;
    }
}

WW_EXPORT void         tlsclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *tlsclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t tlsclientTunnelApi(tunnel_t *instance, sbuf_t *message);
WW_EXPORT void         tlsclientTunnelEnableHandshakeTakeover(tunnel_t *t);
WW_EXPORT bool         tlsclientTunnelIsHandshakeCompleted(tunnel_t *t, line_t *l);
WW_EXPORT bool         tlsclientTunnelGetHandshakeBinding(tunnel_t *t, line_t *l,
                                                          tlsclient_handshake_binding_t *binding);
WW_EXPORT bool         tlsclientTunnelDeinitAfterHandshake(tunnel_t *t, line_t *l, sbuf_t **pending_raw);
WW_EXPORT bool         tlsclientTunnelBeginTakeoverDrain(tunnel_t *t, line_t *l, sbuf_t **pending_raw);
WW_EXPORT tlsclient_post_handshake_result_t
tlsclientTunnelConsumePostHandshakeRecord(tunnel_t *t, line_t *l, sbuf_t *record);
WW_EXPORT bool tlsclientTunnelCompleteTakeover(tunnel_t *t, line_t *l);

void tlsclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void tlsclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void tlsclientTunnelOnPrepair(tunnel_t *t);
void tlsclientTunnelOnStart(tunnel_t *t);
void tlsclientTunnelOnStop(tunnel_t *t);

void tlsclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void tlsclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void tlsclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void tlsclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tlsclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void tlsclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void tlsclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void tlsclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void tlsclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void tlsclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tlsclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void tlsclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void tlsclientLinestateInitialize(tlsclient_lstate_t *ls, SSL_CTX *sctx, buffer_pool_t *pool);
void tlsclientLinestateDestroy(tlsclient_lstate_t *ls);
void tlsclientLinestateRelease(tlsclient_lstate_t *ls);
void tlsclientCloseLineBidirectional(tunnel_t *t, line_t *l);
bool tlsclientTakeoverTryReadRecord(tlsclient_lstate_t *ls, sbuf_t **record, bool *invalid);
bool tlsclientFlushSslOutput(tunnel_t *t, line_t *l, tlsclient_lstate_t *ls);
bool tlsclientSslReadBoundaryIsClean(tlsclient_lstate_t *ls);

void tlsclientPrintSSLState(const SSL *ssl);
void tlsclientPrintSSLError(void);
void tlsclientPrintSSLErrorAndAbort(void);
bool tlsclientConfigureSslForConnect(SSL *ssl, BIO *rbio, BIO *wbio, const char *sni,
                                     const uint8_t *ech_grease_override_payload,
                                     size_t         ech_grease_override_payload_len);
bool tlsclientCreateClientHelloFromContext(SSL_CTX *ssl_ctx, const char *sni,
                                           const uint8_t *ech_grease_override_payload,
                                           size_t ech_grease_override_payload_len, sbuf_t **out);
bool tlsclientCreateEchGreaseInnerClientHello(tlsclient_tstate_t *ts, wid_t wid, sbuf_t **out);
void tlsclientTunnelstateDestroy(tlsclient_tstate_t *ts);
