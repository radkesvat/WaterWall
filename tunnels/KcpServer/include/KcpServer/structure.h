#pragma once

#include "wwapi.h"

#include "KcpCommon/session.h"

typedef struct kcpserver_carrier_s kcpserver_carrier_t;
typedef struct kcpserver_session_s kcpserver_session_t;

typedef struct kcpserver_worker_s
{
    kcpserver_carrier_t *carriers; // Session/timer roots, including detached service drains.
    bool                 quiescing;
} kcpserver_worker_t;

typedef struct kcpserver_tstate_s
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
    kcpserver_worker_t *workers;

} kcpserver_tstate_t;

typedef enum kcpserver_line_kind_e
{
    kKcpServerCarrier = 1, // Borrowed normal UDP-facing line.
    kKcpServerService = 2, // Owned normal application-facing line.
} kcpserver_line_kind_t;

typedef struct kcpserver_lstate_s
{
    kcpserver_line_kind_t kind;
    kcpserver_carrier_t  *carrier;
    kcpserver_session_t  *session;
} kcpserver_lstate_t;

struct kcpserver_session_s
{
    kcpserver_carrier_t *carrier;
    kcpserver_session_t *next;
    kcpserver_session_t *prev;
    tou_session_t       *engine;
    line_t              *service; // Creator reference; detached before Finish callouts.
    bool                 init_entered;
    bool                 carrier_pause_delivered;
    tou_settings_t       offered_settings;
};

struct kcpserver_carrier_s
{
    tunnel_t            *tunnel;
    line_t              *line; // Physical reference only; never owns logical destruction.
    buffer_pool_t       *pool; // Owner pool outlives all session cleanup, including a dead carrier.
    wid_t                wid;
    kcpserver_carrier_t *next;
    kcpserver_carrier_t *prev;
    kcpserver_session_t *sessions;
    size_t               session_count;
    uint32_t             refs;
    wtimer_t            *pending_timer;
    uint64_t             pending_deadline;
    uint8_t              client_nonce[kTouNonceSize];
    uint8_t              server_nonce[kTouNonceSize];
    tou_settings_t       pending_settings;
    tou_settings_t       offered_settings;
    buffer_queue_t       input;
    buffer_budget_t      input_budget;
    bool                 driving;
    bool                 pending;
    bool                 active;
    bool                 transport_established;
    bool                 transport_paused;
};

enum
{
    kTunnelStateSize                 = sizeof(kcpserver_tstate_t),
    kLineStateSize                   = sizeof(kcpserver_lstate_t),
    kFrameHeaderLength               = 1,
    kFrameFlagData                   = 0x00,
    kFrameFlagPing                   = 0xF0,
    kFrameFlagClose                  = 0xFF,
    kKcpServerFecDefaultDataShards   = 10,
    kKcpServerFecDefaultParityShards = 3,
    // the smallest MTU ikcp_setmtu() accepts; anything below it is rejected with -1
    kKcpServerKcpMinimumMtu  = 50,
    kKcpServerIpv4HeaderSize = 20,
    kKcpServerUdpHeaderSize  = 8,
    kKcpServerKcpHeaderSize  = 24,
    kKcpServerKcpMaximumMtu  = kTouMaximumKcpPacketSize,
};

enum kcpserver_kcpsettings_e
{
    kKcpServerKcpNodelayDefault             = 1,
    kKcpServerKcpIntervalDefault            = 10,
    kKcpServerKcpResendDefault              = 2,
    kKcpServerKcpNoCongestionControlDefault = 1,
    kKcpServerKcpSendWindowDefault          = 8192,
    kKcpServerKcpRecvWindowDefault          = 8192,
    kKcpServerKcpInitialCwndDefault         = 4096,
    kKcpServerKcpRxMinRtoDefault            = 30,
    kKcpServerKcpSendBufferLimitDefault     = 0,
    kKcpServerPingintervalMsDefault         = 10000,
    kKcpServerNoRecvTimeOutDefault          = 30000,
    kKcpServerCloseDrainTimeOutDefault      = kTouDefaultCloseMs,
};

static inline uint32_t kcpserverGetOuterFecOverhead(const kcpserver_tstate_t *ts)
{
    assert(ts != NULL);
    return ts->fec_enabled ? kKcpFecOuterHeaderSize : 0;
}

static inline int kcpserverGetKcpMtu(const kcpserver_tstate_t *ts)
{
    const int budget = (int) ts->send_mtu - kKcpServerIpv4HeaderSize - kKcpServerUdpHeaderSize - kTouEnvelopeSize -
                       (int) kcpserverGetOuterFecOverhead(ts);
    return min(budget, kKcpServerKcpMaximumMtu);
}

static inline int kcpserverGetKcpWriteMtu(const kcpserver_tstate_t *ts)
{
    return kcpserverGetKcpMtu(ts) - kKcpServerKcpHeaderSize - kFrameHeaderLength;
}

WW_EXPORT tunnel_t    *kcpserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t kcpserverTunnelApi(tunnel_t *instance, sbuf_t *message);
void                   kcpserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
void                   kcpserverTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void                   kcpserverTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void                   kcpserverTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void                   kcpserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void                   kcpserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void                   kcpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void                   kcpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void                   kcpserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void                   kcpserverTunnelUpStreamResume(tunnel_t *t, line_t *l);
void                   kcpserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void                   kcpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void                   kcpserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void                   kcpserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void                   kcpserverTunnelDownStreamResume(tunnel_t *t, line_t *l);
bool                   kcpserverLinestateInitialize(kcpserver_lstate_t *ls, line_t *l, tunnel_t *t);
void                   kcpserverLinestateDestroy(kcpserver_lstate_t *ls);
void                   kcpserverCarrierRetain(kcpserver_carrier_t *carrier);
void                   kcpserverCarrierRelease(kcpserver_carrier_t *carrier);
void                   kcpserverCarrierClose(kcpserver_carrier_t *carrier, bool notify_owner);
void                   kcpserverRetireService(kcpserver_session_t *session, bool notify_service);
void                   kcpserverCarrierInput(kcpserver_carrier_t *carrier, sbuf_t *buf);
void kcpserverCarrierControl(kcpserver_carrier_t *carrier, uint8_t kind, const uint8_t client[kTouNonceSize],
                             const uint8_t server[kTouNonceSize], const tou_settings_t *settings);

bool kcpserverArmPending(kcpserver_carrier_t *carrier, uint64_t deadline);
void kcpserverRelayToServices(kcpserver_carrier_t *carrier, TunnelFlowRoutineEst callback, bool pressure);
