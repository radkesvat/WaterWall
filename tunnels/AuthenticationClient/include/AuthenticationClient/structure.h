#pragma once

#include "interface.h"

typedef struct authenticationclient_pending_request_s
{
    uint32_t correlation_id;
    uint32_t created_at_ms;
    uint8_t  request_type;
} authenticationclient_pending_request_t;

typedef struct authenticationclient_tstate_s
{
    char *name;
    char *secret;

    users_t  *users;
    users_t  *sync_baseline_users;
    users_t  *pending_push_users;
    wrwlock_t users_lock;
    uint64_t  users_generation;

    wmutex_t control_mutex;
    bool     started;
    bool     stopping;
    bool     connected;
    bool     authenticated;
    bool     write_paused;
    bool     auth_in_flight;
    bool     pull_in_flight;
    bool     push_in_flight;
    bool     first_usage_push_requested;
    bool     first_usage_push_deferred;
    bool     users_loaded;
    bool     verbose;

    line_t   *control_line;
    wtimer_t *ping_timer;
    wtimer_t *sync_timer;
    wtimer_t *reconnect_timer;

    uint8_t  token[64];
    uint32_t next_correlation_id;
    uint32_t ping_interval_ms;
    uint32_t pull_interval_ms;
    uint32_t push_interval_ms;
    uint32_t reconnect_interval_ms;
    uint32_t request_timeout_ms;
    uint32_t max_pending_requests;

    uint64_t remote_config_revision;
    uint64_t remote_stats_revision;
    uint64_t remote_revision_generation;
    uint64_t local_config_revision;
    uint64_t local_stats_revision;
    uint64_t local_revision_generation;

    uint32_t last_pull_sync_ms;
    uint32_t last_push_sync_ms;

    authenticationclient_pending_request_t *pending_requests;
    uint32_t                                pending_count;
    uint32_t                                pending_capacity;
} authenticationclient_tstate_t;

typedef struct authenticationclient_lstate_s
{
    buffer_stream_t read_stream;
} authenticationclient_lstate_t;

enum
{
    kTunnelStateSize = sizeof(authenticationclient_tstate_t),
    kLineStateSize   = sizeof(authenticationclient_lstate_t),

    kAuthenticationClientMessageHeaderSize  = 4,
    kAuthenticationClientSessionTokenSize   = 64,
    kAuthenticationClientRevisionHeaderSize = 16,
    kAuthenticationClientRequestEnvelopeHeaderSize =
        kAuthenticationClientMessageHeaderSize + kAuthenticationClientSessionTokenSize,
    kAuthenticationClientResponseEnvelopeHeaderSize =
        kAuthenticationClientMessageHeaderSize + kAuthenticationClientRevisionHeaderSize,
    kAuthenticationClientCorrelationIdSize  = 4,
    kAuthenticationClientRequestHeaderSize  = 1 + kAuthenticationClientCorrelationIdSize + 4,
    kAuthenticationClientResponseHeaderSize = 1 + kAuthenticationClientCorrelationIdSize + 4,
    kAuthenticationClientMaxMessagePayload  = 16U * 1024U * 1024U,
    kAuthenticationClientMaxRequestData     = 16U * 1024U * 1024U,
    kAuthenticationClientMaxResponsePayload = 16U * 1024U * 1024U,

    kAuthenticationClientRequestTypePing                      = 1,
    kAuthenticationClientRequestTypeGetUserBySHA256Hex        = 2,
    kAuthenticationClientRequestTypeGetUserBySHA256Base64     = 3,
    kAuthenticationClientRequestTypeGetUserBySHA256           = 4,
    kAuthenticationClientRequestTypeGetUserByPassword         = 5,
    kAuthenticationClientRequestTypeAddNewUser                = 6,
    kAuthenticationClientRequestTypeUpdateUser                = 7,
    kAuthenticationClientRequestTypeUpdateUserTraficStatsDiff = 8,
    kAuthenticationClientRequestTypeGetAllUsers               = 9,
    kAuthenticationClientRequestTypeAuthenticate              = 10,
    kAuthenticationClientRequestTypePushUserStats             = 11,
    kAuthenticationClientRequestTypeGetUserBySHA224Hex        = 12,
    kAuthenticationClientRequestTypeGetUserBySHA224Base64     = 13,
    kAuthenticationClientRequestTypeGetUserBySHA224           = 14,

    kAuthenticationClientResponseTypeOk      = 0,
    kAuthenticationClientResponseTypeError   = 0xFF,
    kAuthenticationClientResponseTypePong    = 1,
    kAuthenticationClientResponseTypeUser    = 2,
    kAuthenticationClientResponseTypeUsers   = 3,
    kAuthenticationClientResponseTypeSession = 4,

    kAuthenticationClientDefaultPingIntervalMs      = 60U * 1000U,
    kAuthenticationClientDefaultPullIntervalMs      = 5U * 60U * 1000U,
    kAuthenticationClientDefaultPushIntervalMs      = 5U * 60U * 1000U,
    kAuthenticationClientDefaultReconnectIntervalMs = 5U * 1000U,
    kAuthenticationClientDefaultRequestTimeoutMs    = 120U * 1000U,
    kAuthenticationClientDefaultMaxPendingRequests  = 64U
};

WW_EXPORT void         authenticationclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *authenticationclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t authenticationclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void authenticationclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void authenticationclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void authenticationclientTunnelOnPrepair(tunnel_t *t);
void authenticationclientTunnelOnStart(tunnel_t *t);
void authenticationclientTunnelOnStop(tunnel_t *t);
void authenticationclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid);

void authenticationclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void authenticationclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void authenticationclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void authenticationclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void authenticationclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void authenticationclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void authenticationclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void authenticationclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void authenticationclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void authenticationclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void authenticationclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void authenticationclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void authenticationclientLinestateInitialize(authenticationclient_lstate_t *ls, buffer_pool_t *pool);
void authenticationclientLinestateDestroy(authenticationclient_lstate_t *ls);

void authenticationclientOpenControlLine(tunnel_t *t);
void authenticationclientCloseControlLine(tunnel_t *t, line_t *l, bool propagate_finish);
void authenticationclientScheduleReconnect(tunnel_t *t);
void authenticationclientReconnectTimerCallback(wtimer_t *timer);
void authenticationclientPingTimerCallback(wtimer_t *timer);
void authenticationclientStartSyncTimer(tunnel_t *t);
void authenticationclientSyncTimerCallback(wtimer_t *timer);

bool authenticationclientSendAuthenticate(tunnel_t *t);
bool authenticationclientSendPing(tunnel_t *t);
bool authenticationclientSendGetAllUsers(tunnel_t *t);
bool authenticationclientSendPushUserStats(tunnel_t *t);
bool authenticationclientProcessResponses(tunnel_t *t, line_t *l, authenticationclient_lstate_t *ls);


static inline uint64_t authenticationclientLocalTimeMS(void)
{
    return getHRTimeUs() / 1000ULL;
}
