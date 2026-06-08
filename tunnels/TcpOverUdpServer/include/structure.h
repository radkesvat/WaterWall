#pragma once

#include "wwapi.h"

#include "ikcp.h"
#include "ww_fec.h"

typedef struct tcpoverudpserver_tstate_s
{
    bool     fec_enabled;
    uint8_t  fec_data_shards;
    uint8_t  fec_parity_shards;
    bool     kcp_nodelay;
    bool     kcp_no_congestion_control;
    int      kcp_interval_ms;
    int      kcp_resend;
    int      kcp_send_window;
    int      kcp_recv_window;
    int      kcp_initial_cwnd;
    int      kcp_rx_minrto_ms;
    int      kcp_send_buffer_limit;
    uint32_t ping_interval_ms;
    uint32_t no_recv_timeout_ms;

} tcpoverudpserver_tstate_t;

typedef struct tcpoverudpserver_lstate_s
{
    tunnel_t                 *tunnel;       // our tunnel
    line_t                   *line;         // our line
    ikcpcb                   *k_handle;     // kcp handle
    wtimer_t                 *k_timer;      // kcp processing loop timer
    tcpoverudp_fec_encoder_t *fec_encoder;  // optional fec encoder
    tcpoverudp_fec_decoder_t *fec_decoder;  // optional fec decoder
    uint64_t                  last_recv;    // last received timestamp
    context_queue_t           cq_u;         // context queue upstream
    context_queue_t           cq_d;         // context queue downstream
    bool                      write_paused; // write pause state
    bool                      can_upstream; // can upstream data
    bool                      ping_sent;    // ping sent state

} tcpoverudpserver_lstate_t;

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
};

static inline uint32_t tcpoverudpserverGetOuterFecOverhead(const tcpoverudpserver_tstate_t *ts)
{
    if (ts != NULL && ts->fec_enabled)
    {
        return kTcpOverUdpFecOuterHeaderSize;
    }
    return 0;
}

static inline int tcpoverudpserverGetKcpMtu(const tcpoverudpserver_tstate_t *ts)
{
    return (int) (GLOBAL_MTU_SIZE - tcpoverudpserverGetOuterFecOverhead(ts));
}

static inline int tcpoverudpserverGetKcpWriteMtu(const tcpoverudpserver_tstate_t *ts)
{
    return (int) (GLOBAL_MTU_SIZE - 20 - 8 - 24 - kFrameHeaderLength - tcpoverudpserverGetOuterFecOverhead(ts));
}

static inline int tcpoverudpserverGetKcpSendBufferLimit(const tcpoverudpserver_lstate_t *ls)
{
    const tcpoverudpserver_tstate_t *ts = tunnelGetState(ls->tunnel);
    if (ts->kcp_send_buffer_limit > 0)
    {
        return ts->kcp_send_buffer_limit;
    }

    return (int) (ls->k_handle->snd_wnd + ls->k_handle->rmt_wnd + 10U);
}

WW_EXPORT void         tcpoverudpserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *tcpoverudpserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t tcpoverudpserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void tcpoverudpserverTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void tcpoverudpserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void tcpoverudpserverTunnelOnPrepair(tunnel_t *t);
void tcpoverudpserverTunnelOnStart(tunnel_t *t);
void tcpoverudpserverTunnelOnStop(tunnel_t *t);

void tcpoverudpserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void tcpoverudpserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void tcpoverudpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void tcpoverudpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tcpoverudpserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void tcpoverudpserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void tcpoverudpserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void tcpoverudpserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void tcpoverudpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void tcpoverudpserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tcpoverudpserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void tcpoverudpserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void tcpoverudpserverLinestateInitialize(tcpoverudpserver_lstate_t *ls, line_t *l, tunnel_t *t);
void tcpoverudpserverLinestateDestroy(tcpoverudpserver_lstate_t *ls);

int  tcpoverudpserverKUdpOutput(const char *data, int len, ikcpcb *kcp, void *user);
bool tcpoverudpserverInputKcpPacket(void *ctx, const uint8_t *packet, size_t packet_len);

void tcpoverudpserverKcpLoopIntervalCallback(wtimer_t *timer);
bool tcpoverudpserverUpdateKcp(tcpoverudpserver_lstate_t *ls, bool flush);
