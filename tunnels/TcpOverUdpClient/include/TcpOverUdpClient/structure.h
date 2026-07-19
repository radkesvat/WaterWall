#pragma once

#include "wwapi.h"

#include "ikcp.h"
#include "ww_fec.h"

typedef struct tcpoverudpclient_tstate_s
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
} tcpoverudpclient_tstate_t;

typedef struct tcpoverudpclient_lstate_s
{
    tunnel_t                 *tunnel;         // our tunnel
    line_t                   *line;           // our line
    ikcpcb                   *k_handle;       // kcp handle
    wtimer_t                 *k_timer;        // kcp processing loop timer
    tcpoverudp_fec_encoder_t *fec_encoder;    // optional fec encoder
    tcpoverudp_fec_decoder_t *fec_decoder;    // optional fec decoder
    uint64_t                  last_recv;      // last received timestamp
    context_queue_t           cq_u;           // context queue upstream
    context_queue_t           cq_d;           // context queue downstream
    bool                      write_paused;   // write pause state
    bool                      can_downstream; // can downstream data
    bool                      ping_sent;      // ping sent state

} tcpoverudpclient_lstate_t;

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
    if (ts != NULL && ts->fec_enabled)
    {
        return kTcpOverUdpFecOuterHeaderSize;
    }
    return 0;
}

static inline int tcpoverudpclientGetKcpMtu(const tcpoverudpclient_tstate_t *ts)
{
    return (int) (GLOBAL_MTU_SIZE - tcpoverudpclientGetOuterFecOverhead(ts));
}

static inline int tcpoverudpclientGetKcpWriteMtu(const tcpoverudpclient_tstate_t *ts)
{
    return (int) (GLOBAL_MTU_SIZE - 20 - 8 - 24 - kFrameHeaderLength - tcpoverudpclientGetOuterFecOverhead(ts));
}

static inline int tcpoverudpclientGetKcpSendBufferLimit(const tcpoverudpclient_lstate_t *ls)
{
    const tcpoverudpclient_tstate_t *ts = tunnelGetState(ls->tunnel);
    if (ts->kcp_send_buffer_limit > 0)
    {
        return ts->kcp_send_buffer_limit;
    }

    return (int) (ls->k_handle->snd_wnd + ls->k_handle->rmt_wnd + 10U);
}

WW_EXPORT void         tcpoverudpclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *tcpoverudpclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t tcpoverudpclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void tcpoverudpclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint32_t *mem_offset);
void tcpoverudpclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void tcpoverudpclientTunnelOnPrepair(tunnel_t *t);
void tcpoverudpclientTunnelOnStart(tunnel_t *t);
void tcpoverudpclientTunnelOnStop(tunnel_t *t);

void tcpoverudpclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void tcpoverudpclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void tcpoverudpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void tcpoverudpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tcpoverudpclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void tcpoverudpclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void tcpoverudpclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void tcpoverudpclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void tcpoverudpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void tcpoverudpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tcpoverudpclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void tcpoverudpclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void tcpoverudpclientLinestateInitialize(tcpoverudpclient_lstate_t *ls, line_t *l, tunnel_t *t);
void tcpoverudpclientLinestateDestroy(tcpoverudpclient_lstate_t *ls);

int  tcpoverudpclientKUdpOutput(const char *data, int len, ikcpcb *kcp, void *user);
bool tcpoverudpclientInputKcpPacket(void *ctx, const uint8_t *packet, size_t packet_len);

void tcpoverudpclientKcpLoopIntervalCallback(wtimer_t *timer);
bool tcpoverudpclientUpdateKcp(tcpoverudpclient_lstate_t *ls, bool flush);
