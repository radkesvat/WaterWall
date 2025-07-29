#pragma once

#include "wwapi.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

typedef struct tlsclient_tstate_s
{
    // settings
    char *alpn;
    char *sni;
    bool  verify;

    // state
    SSL_CTX **threadlocal_ssl_contexts;
} tlsclient_tstate_t;

typedef struct tlsclient_lstate_s
{
    SSL           *ssl;
    BIO           *rbio;
    BIO           *wbio;
    buffer_queue_t bq;
    bool           handshake_completed;
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

void tlsclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void tlsclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void tlsclientTunnelOnPrepair(tunnel_t *t);
void tlsclientTunnelOnStart(tunnel_t *t);

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

void tlsclientLinestateInitialize(tlsclient_lstate_t *ls, SSL_CTX *sctx);
void tlsclientLinestateDestroy(tlsclient_lstate_t *ls);

void tlsclientPrintSSLState(const SSL *ssl);
void tlsclientPrintSSLError(void);
void tlsclientPrintSSLErrorAndAbort(void);
