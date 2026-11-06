#pragma once

#include "wwapi.h"

#include "TcpOverUdpCommon/session.h"

typedef struct tcpoverudpclient_session_s tcpoverudpclient_session_t;

typedef struct tcpoverudpclient_worker_s
{
    tcpoverudpclient_session_t *sessions;
    bool                        quiescing;
} tcpoverudpclient_worker_t;

typedef struct tcpoverudpclient_tstate_s
{
    uint16_t                   send_mtu; // Immutable configured packet budget.
    atomic_bool                stopping;
    bool                       fec_enabled;
    uint8_t                    fec_data_shards;
    uint8_t                    fec_parity_shards;
    bool                       kcp_nodelay;
    bool                       kcp_no_congestion_control;
    int                        kcp_interval_ms;
    int                        kcp_resend;
    int                        kcp_send_window;
    int                        kcp_recv_window;
    int                        kcp_initial_cwnd;
    int                        kcp_rx_minrto_ms;
    int                        kcp_send_buffer_limit;
    uint32_t                   ping_interval_ms;
    uint32_t                   no_recv_timeout_ms;
    uint32_t                   close_drain_timeout_ms;
    wid_t                      workers_count;
    tcpoverudpclient_worker_t *workers;
} tcpoverudpclient_tstate_t;

/* Application lines are borrowed; transport lines are created and owned here. */
typedef enum tcpoverudpclient_role_e
{
    kTcpOverUdpClientApplication = 1,
    kTcpOverUdpClientTransport,
} tcpoverudpclient_role_t;

typedef struct tcpoverudpclient_lstate_s
{
    tcpoverudpclient_session_t *session;
    tcpoverudpclient_role_t     role;
} tcpoverudpclient_lstate_t;

/* Stable until the common driver's final reference releases destroy_user. */
struct tcpoverudpclient_session_s
{
    tunnel_t                   *tunnel;
    line_t                     *application;
    line_t                     *transport;
    tou_session_t              *driver;
    tcpoverudpclient_session_t *prev;
    tcpoverudpclient_session_t *next;
    wid_t                       wid;
    bool                        next_init_entered;
    bool                        transport_finished;
    bool                        carrier_paused;
};

enum
{
    kTunnelStateSize                        = sizeof(tcpoverudpclient_tstate_t),
    kLineStateSize                          = sizeof(tcpoverudpclient_lstate_t),
    kFrameHeaderLength                      = 1,
    kFrameFlagData                          = 0x00,
    kFrameFlagPing                          = 0xF0,
    kFrameFlagClose                         = 0xFF,
    kTcpOverUdpClientFecDefaultDataShards   = 10,
    kTcpOverUdpClientFecDefaultParityShards = 3,
    // the smallest MTU ikcp_setmtu() accepts; anything below it is rejected with -1
    kTcpOverUdpClientKcpMinimumMtu  = 50,
    kTcpOverUdpClientIpv4HeaderSize = 20,
    kTcpOverUdpClientUdpHeaderSize  = 8,
    kTcpOverUdpClientKcpHeaderSize  = 24,
    kTcpOverUdpClientKcpMaximumMtu  = kTouMaximumKcpPacketSize,
};

enum tcpoverudpclient_kcpsettings_e
{
    kTcpOverUdpClientKcpNodelayDefault             = 1,
    kTcpOverUdpClientKcpIntervalDefault            = 10,
    kTcpOverUdpClientKcpResendDefault              = 2,
    kTcpOverUdpClientKcpNoCongestionControlDefault = 1,
    kTcpOverUdpClientKcpSendWindowDefault          = 8192,
    kTcpOverUdpClientKcpRecvWindowDefault          = 8192,
    kTcpOverUdpClientKcpInitialCwndDefault         = 4096,
    kTcpOverUdpClientKcpRxMinRtoDefault            = 30,
    kTcpOverUdpClientKcpSendBufferLimitDefault     = 0,
    kTcpOverUdpClientPingintervalMsDefault         = 10000,
    kTcpOverUdpClientNoRecvTimeOutDefault          = 30000,
};

static inline uint32_t tcpoverudpclientGetOuterFecOverhead(const tcpoverudpclient_tstate_t *ts)
{
    return ts->fec_enabled ? kTcpOverUdpFecOuterHeaderSize : 0;
}

static inline int tcpoverudpclientGetKcpMtu(const tcpoverudpclient_tstate_t *ts)
{
    const int budget = (int) ts->send_mtu - kTcpOverUdpClientIpv4HeaderSize - kTcpOverUdpClientUdpHeaderSize -
                       kTouEnvelopeSize - (int) tcpoverudpclientGetOuterFecOverhead(ts);
    return min(budget, kTcpOverUdpClientKcpMaximumMtu);
}

static inline int tcpoverudpclientGetKcpWriteMtu(const tcpoverudpclient_tstate_t *ts)
{
    return tcpoverudpclientGetKcpMtu(ts) - kTcpOverUdpClientKcpHeaderSize - kFrameHeaderLength;
}

WW_EXPORT tunnel_t    *tcpoverudpclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t tcpoverudpclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void tcpoverudpclientTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void tcpoverudpclientTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void tcpoverudpclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void tcpoverudpclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);

void tcpoverudpclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void tcpoverudpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void tcpoverudpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void tcpoverudpclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void tcpoverudpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void tcpoverudpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tcpoverudpclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void tcpoverudpclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void tcpoverudpclientLinestateDestroy(tcpoverudpclient_lstate_t *ls);
bool tcpoverudpclientSessionCreate(tunnel_t *t, line_t *application);
void tcpoverudpclientDetachApplication(tcpoverudpclient_session_t *session, bool notify);
void tcpoverudpclientSignalApplication(tcpoverudpclient_session_t *session, LineTaskFnNoBuf signal);
void tcpoverudpclientSetCarrierPaused(tcpoverudpclient_session_t *session, bool paused);
void tcpoverudpclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void tcpoverudpclientTunnelUpStreamResume(tunnel_t *t, line_t *l);
