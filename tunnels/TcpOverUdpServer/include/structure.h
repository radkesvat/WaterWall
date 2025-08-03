#pragma once

#include "wwapi.h"

#include "ikcp.h"

typedef struct tcpoverudpserver_tstate_s
{
    atomic_uint session_identifier;

} tcpoverudpserver_tstate_t;

typedef struct tcpoverudpserver_lstate_s
{
    tunnel_t *tunnel;       // our tunnel
    line_t   *line;         // our line
    ikcpcb   *k_handle;     // kcp handle
    wtimer_t *k_timer;      // kcp processing loop timer
    bool      write_paused; // write pause state
} tcpoverudpserver_lstate_t;

enum
{
    kTunnelStateSize = sizeof(tcpoverudpserver_tstate_t),
    kLineStateSize   = sizeof(tcpoverudpserver_lstate_t)
};

enum tcpoverudpserver_kcpsettings_e
{
    kTcpOverUdpServerKcpNodelay  = 1,  // enable nodelay
    kTcpOverUdpServerKcpInterval = 10, // interval for sending data
    kTcpOverUdpServerKcpResend   = 2,  // resend count
    kTcpOverUdpServerKcpStream   = 0,  // stream mode
};

// 1400 - 20 (IP) - 8 (UDP) - ~24 (KCP) ≈ 1348 bytes
#define KCP_MTU               (GLOBAL_MTU_SIZE - 20 - 8 - 24)
#define KCP_SEND_WINDOW_LIMIT 512

WW_EXPORT void         tcpoverudpserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *tcpoverudpserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t tcpoverudpserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void tcpoverudpserverTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void tcpoverudpserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void tcpoverudpserverTunnelOnPrepair(tunnel_t *t);
void tcpoverudpserverTunnelOnStart(tunnel_t *t);

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

int tcpoverudpserverKUdpOutput(const char *data, int len, ikcpcb *kcp, void *user);

void tcpoverudpserverKcpLoopIntervalCallback(wtimer_t *timer);
