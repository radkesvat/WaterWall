#pragma once

#include "wwapi.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

typedef enum tlsclient_sni_selection_e
{
    kTlsClientSniSelectionFixed = 0,
    kTlsClientSniSelectionRoundRobin,
    kTlsClientSniSelectionRandom,
    kTlsClientSniSelectionRace,
    kTlsClientSniSelectionHealthyOnly,
    kTlsClientSniSelectionLeastRtt,
    kTlsClientSniSelectionWeightedRoundRobin,
} tlsclient_sni_selection_e;

typedef enum tlsclient_line_role_e
{
    kTlsClientLineRoleNormal = 0,
    kTlsClientLineRoleRaceMain,
    kTlsClientLineRoleRaceChild,
} tlsclient_line_role_e;

typedef struct tlsclient_sni_stat_s
{
    atomic_uint successes;
    atomic_uint failures;
    atomic_uint consecutive_failures;
    atomic_uint active_lines;
    atomic_uint healthy;
    atomic_uint rtt_ema_ms;
    uint32_t    weight;
} tlsclient_sni_stat_t;

typedef struct tlsclient_tstate_s
{
    // settings
    char *alpn;
    char **snis;
    uint32_t snis_count;
    tlsclient_sni_selection_e sni_selection;
    atomic_uint sni_round_index;
    atomic_uint sni_weight_index;
    uint32_t    sni_weight_total;
    uint32_t    race_tries;
    uint32_t    race_timeout_ms;
    uint32_t    sni_max_consecutive_failures;
    uint32_t    sni_probe_interval_ms;
    uint32_t    min_unused_per_sni;
    tlsclient_sni_stat_t *sni_stats;
    char *ech_grease_sni_override;
    bool  verify;
    bool  x25519mlkem768_enabled;
    bool  handshake_takeover_enabled;

    // state
    SSL_CTX **threadlocal_ssl_contexts;
    SSL_CTX **threadlocal_ech_grease_inner_ssl_contexts;
} tlsclient_tstate_t;

typedef struct tlsclient_lstate_s
{
    SSL           *ssl;
    BIO           *rbio;
    BIO           *wbio;
    buffer_queue_t bq;
    bool           handshake_completed;
    bool           handshake_est_sent;
    bool           resources_released;
    bool           passthrough;
    tlsclient_line_role_e role;
    const char            *selected_sni;
    uint32_t               selected_sni_index;
    bool                   sni_success_recorded;
    bool                   sni_failure_recorded;
    bool                   sni_active_tracked;
    uint64_t               handshake_start_ms;

    line_t       **race_child_lines;
    line_t        *race_selected_child;
    line_t        *race_main_line;
    uint32_t       race_child_count;
    uint32_t       race_child_slot;
    uint32_t       race_open_children;
    bool           race_main_est_forwarded;
    buffer_queue_t race_pending_up;
} tlsclient_lstate_t;

enum
{
    kTlsClientDefaultRaceTimeoutMs             = 5000,
    kTlsClientRaceMaxPendingUpBytes            = 1024 * 1024,
    kTlsClientRacePendingQueueCap              = 8,
    kTlsClientDefaultSniWeight                 = 1,
    kTlsClientDefaultSniMaxConsecutiveFailures = 3,
    kTlsClientUnknownRttMs                     = UINT32_MAX,
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
WW_EXPORT void         tlsclientTunnelEnableHandshakeTakeover(tunnel_t *t);
WW_EXPORT bool         tlsclientTunnelIsHandshakeCompleted(tunnel_t *t, line_t *l);
WW_EXPORT bool         tlsclientTunnelDeinitAfterHandshake(tunnel_t *t, line_t *l, sbuf_t **pending_raw);

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

void tlsclientLinestateInitialize(tlsclient_lstate_t *ls, SSL_CTX *sctx);
void tlsclientLinestateSetupSsl(tlsclient_lstate_t *ls, SSL_CTX *sctx);
void tlsclientLinestateDestroy(tlsclient_lstate_t *ls);
void tlsclientLinestateRelease(tlsclient_lstate_t *ls);

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
