#pragma once

#include "wwapi.h"

#include "KcpCommon/session.h"

typedef struct kcpclient_session_s kcpclient_session_t;

typedef struct kcpclient_worker_s
{
    kcpclient_session_t *sessions;
    bool                 quiescing;
} kcpclient_worker_t;

typedef struct kcpclient_tstate_s
{
    uint16_t            send_mtu; // Immutable configured packet budget.
    atomic_bool         stopping;
    bool                fec_enabled;
    uint8_t             fec_data_shards;
    uint8_t             fec_parity_shards;
    bool                kcp_nodelay;
    bool                kcp_no_congestion_control;
    int                 kcp_interval_ms;
    int                 kcp_resend;
    int                 kcp_send_window;
    int                 kcp_recv_window;
    int                 kcp_initial_cwnd;
    int                 kcp_rx_minrto_ms;
    int                 kcp_send_buffer_limit;
    uint32_t            ping_interval_ms;
    uint32_t            no_recv_timeout_ms;
    uint32_t            close_drain_timeout_ms;
    wid_t               workers_count;
    kcpclient_worker_t *workers;
} kcpclient_tstate_t;

/* Application lines are borrowed; transport lines are created and owned here. */
typedef enum kcpclient_role_e
{
    kKcpClientApplication = 1,
    kKcpClientTransport,
} kcpclient_role_t;

typedef struct kcpclient_lstate_s
{
    kcpclient_session_t *session;
    kcpclient_role_t     role;
} kcpclient_lstate_t;

/* Stable until the common driver's final reference releases destroy_user. */
struct kcpclient_session_s
{
    tunnel_t            *tunnel;
    line_t              *application;
    line_t              *transport;
    tou_session_t       *driver;
    kcpclient_session_t *prev;
    kcpclient_session_t *next;
    wid_t                wid;
    bool                 next_init_entered;
    bool                 transport_finished;
    bool                 carrier_paused;
};

enum
{
    kTunnelStateSize                 = sizeof(kcpclient_tstate_t),
    kLineStateSize                   = sizeof(kcpclient_lstate_t),
    kFrameHeaderLength               = 1,
    kFrameFlagData                   = 0x00,
    kFrameFlagPing                   = 0xF0,
    kFrameFlagClose                  = 0xFF,
    kKcpClientFecDefaultDataShards   = 10,
    kKcpClientFecDefaultParityShards = 3,
    // the smallest MTU ikcp_setmtu() accepts; anything below it is rejected with -1
    kKcpClientKcpMinimumMtu  = 50,
    kKcpClientIpv4HeaderSize = 20,
    kKcpClientUdpHeaderSize  = 8,
    kKcpClientKcpHeaderSize  = 24,
    kKcpClientKcpMaximumMtu  = kTouMaximumKcpPacketSize,
};

enum kcpclient_kcpsettings_e
{
    kKcpClientKcpNodelayDefault             = 1,
    kKcpClientKcpIntervalDefault            = 10,
    kKcpClientKcpResendDefault              = 2,
    kKcpClientKcpNoCongestionControlDefault = 1,
    kKcpClientKcpSendWindowDefault          = 8192,
    kKcpClientKcpRecvWindowDefault          = 8192,
    kKcpClientKcpInitialCwndDefault         = 4096,
    kKcpClientKcpRxMinRtoDefault            = 30,
    kKcpClientKcpSendBufferLimitDefault     = 0,
    kKcpClientPingintervalMsDefault         = 10000,
    kKcpClientNoRecvTimeOutDefault          = 30000,
};

static inline uint32_t kcpclientGetOuterFecOverhead(const kcpclient_tstate_t *ts)
{
    return ts->fec_enabled ? kKcpFecOuterHeaderSize : 0;
}

static inline int kcpclientGetKcpMtu(const kcpclient_tstate_t *ts)
{
    const int budget = (int) ts->send_mtu - kKcpClientIpv4HeaderSize - kKcpClientUdpHeaderSize - kTouEnvelopeSize -
                       (int) kcpclientGetOuterFecOverhead(ts);
    return min(budget, kKcpClientKcpMaximumMtu);
}

static inline int kcpclientGetKcpWriteMtu(const kcpclient_tstate_t *ts)
{
    return kcpclientGetKcpMtu(ts) - kKcpClientKcpHeaderSize - kFrameHeaderLength;
}

WW_EXPORT tunnel_t    *kcpclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t kcpclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void kcpclientTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void kcpclientTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void kcpclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void kcpclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);

void kcpclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void kcpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void kcpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void kcpclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void kcpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void kcpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void kcpclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void kcpclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void kcpclientLinestateDestroy(kcpclient_lstate_t *ls);
bool kcpclientSessionCreate(tunnel_t *t, line_t *application);
void kcpclientDetachApplication(kcpclient_session_t *session, bool notify);
void kcpclientSignalApplication(kcpclient_session_t *session, LineTaskFnNoBuf signal);
void kcpclientSetCarrierPaused(kcpclient_session_t *session, bool paused);
void kcpclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void kcpclientTunnelUpStreamResume(tunnel_t *t, line_t *l);
