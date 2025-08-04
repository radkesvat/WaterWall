#pragma once

#include "wwapi.h"

#include "ikcp.h"

typedef struct tcpoverudpclient_tstate_s
{
    atomic_uint session_identifier;

} tcpoverudpclient_tstate_t;

typedef struct tcpoverudpclient_lstate_s
{
    tunnel_t       *tunnel;             // our tunnel
    line_t         *line;               // our line
    ikcpcb         *k_handle;           // kcp handle
    wtimer_t       *k_timer;            // kcp processing loop timer
    context_queue_t cq_u;               // context queue upstream
    context_queue_t cq_d;               // context queue downstream
    bool            write_paused : 1;   // write pause state
    bool            can_downstream : 1; // can downstream data

} tcpoverudpclient_lstate_t;

enum
{
    kTunnelStateSize   = sizeof(tcpoverudpclient_tstate_t),
    kLineStateSize     = sizeof(tcpoverudpclient_lstate_t),
    kFrameHeaderLength = 1,
    kFrameFlagData     = 0x00,
    kFrameFlagClose    = 0xFF,
};

enum tcpoverudpclient_kcpsettings_e
{
    kTcpOverUdpClientKcpNodelay    = 1,  // enable nodelay
    kTcpOverUdpClientKcpInterval   = 10, // interval for processing kcp stack (ms)
    kTcpOverUdpClientKcpResend     = 1,  // resend count
    kTcpOverUdpClientKcpStream     = 0,  // stream mode
    kTcpOverUdpClientKcpSendWindow = 2048,
    kTcpOverUdpClientKcpRecvWindow = 2048,
};

// 1400 - 20 (IP) - 8 (UDP) - ~24 (KCP) ≈ 1348 bytes
#define KCP_MTU               (GLOBAL_MTU_SIZE)
#define KCP_MTU_WRITE         (GLOBAL_MTU_SIZE - 20 - 8 - 24 - kFrameHeaderLength)
#define KCP_SEND_WINDOW_LIMIT 2048

WW_EXPORT void         tcpoverudpclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *tcpoverudpclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t tcpoverudpclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void tcpoverudpclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void tcpoverudpclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void tcpoverudpclientTunnelOnPrepair(tunnel_t *t);
void tcpoverudpclientTunnelOnStart(tunnel_t *t);

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

int tcpoverudpclientKUdpOutput(const char *data, int len, ikcpcb *kcp, void *user);

void tcpoverudpclientKcpLoopIntervalCallback(wtimer_t *timer);
bool tcpoverudpclientUpdateKcp(tcpoverudpclient_lstate_t *ls, bool flush);
