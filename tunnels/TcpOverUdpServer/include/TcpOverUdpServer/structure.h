#pragma once

#include "wwapi.h"

#include "TcpOverUdpCommon/session.h"

typedef struct tcpoverudpserver_carrier_s tcpoverudpserver_carrier_t;
typedef struct tcpoverudpserver_session_s tcpoverudpserver_session_t;

typedef struct tcpoverudpserver_worker_s
{
    tcpoverudpserver_carrier_t *carriers; // Session/timer roots, including detached service drains.
    bool                        quiescing;
} tcpoverudpserver_worker_t;

typedef struct tcpoverudpserver_tstate_s
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
    tcpoverudpserver_worker_t *workers;

} tcpoverudpserver_tstate_t;

typedef enum tcpoverudpserver_line_kind_e
{
    kTcpOverUdpServerCarrier = 1, // Borrowed normal UDP-facing line.
    kTcpOverUdpServerService = 2, // Owned normal application-facing line.
} tcpoverudpserver_line_kind_t;

typedef struct tcpoverudpserver_lstate_s
{
    tcpoverudpserver_line_kind_t kind;
    tcpoverudpserver_carrier_t  *carrier;
    tcpoverudpserver_session_t  *session;
} tcpoverudpserver_lstate_t;

struct tcpoverudpserver_session_s
{
    tcpoverudpserver_carrier_t *carrier;
    tcpoverudpserver_session_t *next;
    tcpoverudpserver_session_t *prev;
    tou_session_t              *engine;
    line_t                     *service; // Creator reference; detached before Finish callouts.
    bool                        init_entered;
    bool                        carrier_pause_delivered;
    tou_settings_t              offered_settings;
};

struct tcpoverudpserver_carrier_s
{
    tunnel_t                   *tunnel;
    line_t                     *line; // Physical reference only; never owns logical destruction.
    buffer_pool_t              *pool; // Owner pool outlives all session cleanup, including a dead carrier.
    wid_t                       wid;
    tcpoverudpserver_carrier_t *next;
    tcpoverudpserver_carrier_t *prev;
    tcpoverudpserver_session_t *sessions;
    size_t                      session_count;
    uint32_t                    refs;
    wtimer_t                   *pending_timer;
    uint64_t                    pending_deadline;
    uint8_t                     client_nonce[kTouNonceSize];
    uint8_t                     server_nonce[kTouNonceSize];
    tou_settings_t              pending_settings;
    tou_settings_t              offered_settings;
    buffer_queue_t              input;
    buffer_budget_t             input_budget;
    bool                        driving;
    bool                        pending;
    bool                        active;
    bool                        transport_established;
    bool                        transport_paused;
};

enum
{
    kTunnelStateSize                        = sizeof(tcpoverudpserver_tstate_t),
    kLineStateSize                          = sizeof(tcpoverudpserver_lstate_t),
    kFrameHeaderLength                      = 1,
    kFrameFlagData                          = 0x00,
    kFrameFlagPing                          = 0xF0,
    kFrameFlagClose                         = 0xFF,
    kTcpOverUdpServerFecDefaultDataShards   = 10,
    kTcpOverUdpServerFecDefaultParityShards = 3,
    // the smallest MTU ikcp_setmtu() accepts; anything below it is rejected with -1
    kTcpOverUdpServerKcpMinimumMtu  = 50,
    kTcpOverUdpServerIpv4HeaderSize = 20,
    kTcpOverUdpServerUdpHeaderSize  = 8,
    kTcpOverUdpServerKcpHeaderSize  = 24,
    kTcpOverUdpServerKcpMaximumMtu  = kTouMaximumKcpPacketSize,
};

enum tcpoverudpserver_kcpsettings_e
{
    kTcpOverUdpServerKcpNodelayDefault             = 1,
    kTcpOverUdpServerKcpIntervalDefault            = 10,
    kTcpOverUdpServerKcpResendDefault              = 2,
    kTcpOverUdpServerKcpNoCongestionControlDefault = 1,
    kTcpOverUdpServerKcpSendWindowDefault          = 8192,
    kTcpOverUdpServerKcpRecvWindowDefault          = 8192,
    kTcpOverUdpServerKcpInitialCwndDefault         = 4096,
    kTcpOverUdpServerKcpRxMinRtoDefault            = 30,
    kTcpOverUdpServerKcpSendBufferLimitDefault     = 0,
    kTcpOverUdpServerPingintervalMsDefault         = 10000,
    kTcpOverUdpServerNoRecvTimeOutDefault          = 30000,
    kTcpOverUdpServerCloseDrainTimeOutDefault      = kTouDefaultCloseMs,
};

static inline uint32_t tcpoverudpserverGetOuterFecOverhead(const tcpoverudpserver_tstate_t *ts)
{
    assert(ts != NULL);
    return ts->fec_enabled ? kTcpOverUdpFecOuterHeaderSize : 0;
}

static inline int tcpoverudpserverGetKcpMtu(const tcpoverudpserver_tstate_t *ts)
{
    const int budget = (int) ts->send_mtu - kTcpOverUdpServerIpv4HeaderSize - kTcpOverUdpServerUdpHeaderSize -
                       kTouEnvelopeSize - (int) tcpoverudpserverGetOuterFecOverhead(ts);
    return min(budget, kTcpOverUdpServerKcpMaximumMtu);
}

static inline int tcpoverudpserverGetKcpWriteMtu(const tcpoverudpserver_tstate_t *ts)
{
    return tcpoverudpserverGetKcpMtu(ts) - kTcpOverUdpServerKcpHeaderSize - kFrameHeaderLength;
}

WW_EXPORT tunnel_t    *tcpoverudpserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t tcpoverudpserverTunnelApi(tunnel_t *instance, sbuf_t *message);
void                   tcpoverudpserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
void                   tcpoverudpserverTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void tcpoverudpserverTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void tcpoverudpserverTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void tcpoverudpserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void tcpoverudpserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void tcpoverudpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void tcpoverudpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tcpoverudpserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void tcpoverudpserverTunnelUpStreamResume(tunnel_t *t, line_t *l);
void tcpoverudpserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void tcpoverudpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void tcpoverudpserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tcpoverudpserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void tcpoverudpserverTunnelDownStreamResume(tunnel_t *t, line_t *l);
bool tcpoverudpserverLinestateInitialize(tcpoverudpserver_lstate_t *ls, line_t *l, tunnel_t *t);
void tcpoverudpserverLinestateDestroy(tcpoverudpserver_lstate_t *ls);
void tcpoverudpserverCarrierRetain(tcpoverudpserver_carrier_t *carrier);
void tcpoverudpserverCarrierRelease(tcpoverudpserver_carrier_t *carrier);
void tcpoverudpserverCarrierClose(tcpoverudpserver_carrier_t *carrier, bool notify_owner);
void tcpoverudpserverRetireService(tcpoverudpserver_session_t *session, bool notify_service);
void tcpoverudpserverCarrierInput(tcpoverudpserver_carrier_t *carrier, sbuf_t *buf);
void tcpoverudpserverCarrierControl(tcpoverudpserver_carrier_t *carrier, uint8_t kind,
                                    const uint8_t client[kTouNonceSize], const uint8_t server[kTouNonceSize],
                                    const tou_settings_t *settings);

bool tcpoverudpserverArmPending(tcpoverudpserver_carrier_t *carrier, uint64_t deadline);
void tcpoverudpserverRelayToServices(tcpoverudpserver_carrier_t *carrier, TunnelFlowRoutineEst callback, bool pressure);
