#pragma once

#include "wwapi.h"

#include "TlsRecordShapingCommon/record_shaping.h"
#include "crypto/openssl_instance.h"

typedef struct tlsserver_tstate_s
{
    SSL_CTX **threadlocal_ssl_contexts;
    node_t   *fallback_node;
    tunnel_t *fallback_tunnel;

    struct tlsserver_alpn_item_s
    {
        char        *name;
        unsigned int name_length;
    }                            *alpns;
    unsigned int                  alpns_length;
    struct tlsserver_alpn_item_s *select_alpns;
    unsigned int                  select_alpns_length;

    char *expected_sni;
    char *cert_file;
    char *key_file;
    char *ciphers;

    uint8_t      session_id_context[sizeof(hash_t) * 4];
    unsigned int session_id_context_len;

    int                       min_proto_version;
    int                       max_proto_version;
    int                       session_timeout;
    int                       session_cache_mode;
    int                       session_cache_size;
    uint32_t                  handshake_timeout_ms;
    uint32_t                  fallback_intentional_delay_ms;
    uint32_t                  fallback_intentional_delay_jitter_ms;
    tlsrecordshaping_config_t record_shaping;
    bool                      prefer_server_ciphers;
    bool                      session_tickets;
    bool                      verbose;
} tlsserver_tstate_t;

typedef struct tlsserver_lstate_s
{
    tunnel_t                       *tunnel;
    line_t                         *line;
    SSL                            *ssl;
    BIO                            *rbio;
    BIO                            *wbio;
    wtimer_t                       *handshake_deadline_timer;
    wtimer_t                       *shaping_output_timer;
    buffer_queue_t                  pending_down;
    buffer_queue_t                 *fallback_pending_up;
    buffer_stream_t                 fallback_probe;
    tlsrecordshaping_output_queue_t shaping_output;
    tlsrecordshaping_state_t        shaping_state;

    bool handshake_completed;
    bool handshake_deadline_armed;
    bool tls_committed;
    bool fallback_probe_tls_like;
    bool protected_init_sent;
    bool fallback_mode;
    bool fallback_init_sent;
    bool fallback_close_draining;
    bool fallback_branch_finished_during_drain;
    bool fallback_payload_paused;
    bool prev_est_sent;
    bool fallback_delay_scheduled;
    bool upstream_finished;
    bool downstream_finishing;
    bool downstream_finish_deferred;
    bool shaping_wire_paused;
    bool shaping_producer_paused;
    /* Monotonic: once true, an uninitialized shaping_output is intentional. */
    bool shaping_retired;
    bool shaping_timer_failure_logged;
    bool shaping_metadata_error;
    bool shaping_writing_application;
    bool resources_released;
    bool verbose;
} tlsserver_lstate_t;

enum
{
    kTunnelStateSize = sizeof(tlsserver_tstate_t),
    kLineStateSize   = sizeof(tlsserver_lstate_t),

    kTlsServerFallbackBufferQueueCap  = 8,
    kTlsServerMaxFallbackPendingBytes = 1024 * 1024
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

WW_EXPORT void         tlsserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *tlsserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t tlsserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void tlsserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);

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

bool tlsserverLinestateInitialize(tlsserver_lstate_t *ls, SSL_CTX *ssl_ctx, buffer_pool_t *pool,
                                  const tlsrecordshaping_config_t *record_shaping, bool verbose);
void tlsserverLinestateDestroy(tlsserver_lstate_t *ls);
void tlsserverLinestateRelease(tlsserver_lstate_t *ls);

void tlsserverTunnelstateDestroy(tlsserver_tstate_t *ts);

int    tlsserverOnServername(SSL *ssl, int *ad, void *arg);
int    tlsserverOnAlpnSelect(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in,
                             unsigned int inlen, void *arg);
void   tlsserverPrintSSLState(const SSL *ssl);
void   tlsserverPrintSSLError(void);
bool   tlsserverFlushSslOutput(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls);
bool   tlsserverEncryptAndSendApplicationData(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls, sbuf_t *buf);
bool   tlsserverFlushPendingDownQueue(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls);
bool   tlsserverSendCloseNotify(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls);
bool   tlsserverDrainShapedOutput(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls, bool force);
bool   tlsserverScheduleShapedOutput(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls);
void   tlsserverCancelShapedOutputTimer(tlsserver_lstate_t *ls);
bool   tlsserverTryCompleteDeferredFinish(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls);
bool   tlsserverStartProtectedBranch(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls);
bool   tlsserverStartFallback(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls);
bool   tlsserverSendFallbackPayload(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls, sbuf_t *buf);
bool   tlsserverScheduleFallbackPayloadDrain(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls);
void   tlsserverCloseFallbackFromUpstream(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls);
bool   tlsserverArmHandshakeDeadline(tunnel_t *t, line_t *l, tlsserver_lstate_t *ls);
void   tlsserverDisarmHandshakeDeadline(tlsserver_lstate_t *ls);
void   tlsserverCloseLineFatal(tunnel_t *t, line_t *l);
size_t tlsserverRecordPaddingCallback(SSL *ssl, int type, size_t len, void *arg);
void   tlsserverRecordMessageCallback(int write_p, int version, int content_type, const void *buf, size_t len, SSL *ssl,
                                      void *arg);
