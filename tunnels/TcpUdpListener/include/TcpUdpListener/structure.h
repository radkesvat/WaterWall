#pragma once

#include "wwapi.h"

#include "TcpListener/interface.h"
#include "UdpListener/interface.h"

typedef struct tcpudplistener_tstate_s
{
    node_t    tcp_node;
    node_t    udp_node;
    tunnel_t *tcp_listener;
    tunnel_t *udp_listener;
} tcpudplistener_tstate_t;

enum
{
    kTunnelStateSize = sizeof(tcpudplistener_tstate_t),
    kLineStateSize   = 0
};

WW_EXPORT void         tcpudplistenerTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *tcpudplistenerTunnelCreate(node_t *node);
WW_EXPORT api_result_t tcpudplistenerTunnelApi(tunnel_t *instance, sbuf_t *message);

void tcpudplistenerTunnelOnIndex(tunnel_t *t, uint16_t index, uint32_t *mem_offset);
void tcpudplistenerTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void tcpudplistenerTunnelOnPrepair(tunnel_t *t);
void tcpudplistenerTunnelOnStart(tunnel_t *t);
void tcpudplistenerTunnelOnStop(tunnel_t *t);
void tcpudplistenerTunnelOnWorkerStop(tunnel_t *t, wid_t wid);

void tcpudplistenerTunnelUpStreamInit(tunnel_t *t, line_t *l);
void tcpudplistenerTunnelUpStreamEst(tunnel_t *t, line_t *l);
void tcpudplistenerTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void tcpudplistenerTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tcpudplistenerTunnelUpStreamPause(tunnel_t *t, line_t *l);
void tcpudplistenerTunnelUpStreamResume(tunnel_t *t, line_t *l);

void tcpudplistenerTunnelDownStreamInit(tunnel_t *t, line_t *l);
void tcpudplistenerTunnelDownStreamEst(tunnel_t *t, line_t *l);
void tcpudplistenerTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void tcpudplistenerTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tcpudplistenerTunnelDownStreamPause(tunnel_t *t, line_t *l);
void tcpudplistenerTunnelDownStreamResume(tunnel_t *t, line_t *l);

tunnel_t *tcpudplistenerSelectDownStreamTunnel(tunnel_t *t, line_t *l);
void      tcpudplistenerTunnelstateDestroy(tcpudplistener_tstate_t *ts);
