#pragma once

#include "wwapi.h"

#include "crypto/openssl_instance.h"

typedef struct tlsserver_tstate_s
{
    SSL_CTX **threadlocal_ssl_contexts;

    struct tlsserver_alpn_item_s
    {
        char        *name;
        unsigned int name_length;
    } *alpns;
    unsigned int alpns_length;

    char *expected_sni;
    char *cert_file;
    char *key_file;
    char *ciphers;

    uint8_t      session_id_context[sizeof(hash_t) * 4];
    unsigned int session_id_context_len;

    int  min_proto_version;
    int  max_proto_version;
    int  session_timeout;
    int  session_cache_mode;
    int  session_cache_size;
    bool prefer_server_ciphers;
    bool session_tickets;
    bool verbose;
} tlsserver_tstate_t;

typedef struct tlsserver_lstate_s
{
    SSL           *ssl;
    BIO           *rbio;
    BIO           *wbio;
    buffer_queue_t pending_down;

    bool handshake_completed;
    bool next_finished;
    bool prev_finished;
    bool close_notify_sent;
    bool peer_close_notify_received;
    bool resources_released;
    bool verbose;
} tlsserver_lstate_t;

enum
{
    kTunnelStateSize = sizeof(tlsserver_tstate_t),
    kLineStateSize   = sizeof(tlsserver_lstate_t)
};

enum sslstatus
{
    kSslstatusOk,
    kSslstatusWantIo,
    kSslstatusFail
};

enum
{
    kTlsServerSessionCacheNone,
    kTlsServerSessionCacheOff,
    kTlsServerSessionCacheBuiltin
};

static inline enum sslstatus getSslStatus(SSL *ssl, int n)
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

WW_EXPORT void         tlsserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *tlsserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t tlsserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void tlsserverTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void tlsserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void tlsserverTunnelOnPrepair(tunnel_t *t);
void tlsserverTunnelOnStart(tunnel_t *t);

void tlsserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void tlsserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void tlsserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void tlsserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tlsserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void tlsserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void tlsserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void tlsserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void tlsserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void tlsserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tlsserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void tlsserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

bool tlsserverLinestateInitialize(tlsserver_lstate_t *ls, SSL_CTX *ssl_ctx, bool verbose);
void tlsserverLinestateDestroy(tlsserver_lstate_t *ls);
void tlsserverLinestateRelease(tlsserver_lstate_t *ls);

void tlsserverTunnelstateDestroy(tlsserver_tstate_t *ts);

int  tlsserverOnServername(SSL *ssl, int *ad, void *arg);
int  tlsserverOnAlpnSelect(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                           unsigned int inlen, void *arg);
void tlsserverPrintSSLState(const SSL *ssl);
void tlsserverPrintSSLError(void);
bool tlsserverFlushSslOutput(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls);
bool tlsserverEncryptAndSendApplicationData(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls, sbuf_t *buf);
bool tlsserverFlushPendingDownQueue(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls);
bool tlsserverSendCloseNotify(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls);
void tlsserverCloseLineFatal(tunnel_t *t, line_t *l);
