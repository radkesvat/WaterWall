#pragma once

#include "wwapi.h"

#include "TcpConnector/interface.h"
#include "UdpConnector/interface.h"

typedef struct tcpudpconnector_tstate_s
{
    node_t    tcp_node;
    node_t    udp_node;
    tunnel_t *tcp_connector;
    tunnel_t *udp_connector;
} tcpudpconnector_tstate_t;

typedef struct tcpudpconnector_lstate_s
{
    tunnel_t *selected_connector;
} tcpudpconnector_lstate_t;

enum
{
    kTunnelStateSize = sizeof(tcpudpconnector_tstate_t),
    kLineStateSize   = sizeof(tcpudpconnector_lstate_t)
};

WW_EXPORT void         tcpudpconnectorTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *tcpudpconnectorTunnelCreate(node_t *node);
WW_EXPORT api_result_t tcpudpconnectorTunnelApi(tunnel_t *instance, sbuf_t *message);

void tcpudpconnectorTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);

void tcpudpconnectorTunnelUpStreamInit(tunnel_t *t, line_t *l);
void tcpudpconnectorTunnelUpStreamEst(tunnel_t *t, line_t *l);
void tcpudpconnectorTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void tcpudpconnectorTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tcpudpconnectorTunnelUpStreamPause(tunnel_t *t, line_t *l);
void tcpudpconnectorTunnelUpStreamResume(tunnel_t *t, line_t *l);

void tcpudpconnectorTunnelDownStreamFinish(tunnel_t *t, line_t *l);

tunnel_t *tcpudpconnectorSelectUpStreamTunnel(tunnel_t *t, line_t *l);
tunnel_t *tcpudpconnectorGetSelectedUpStreamTunnel(tunnel_t *t, line_t *l);
void      tcpudpconnectorLinestateInitialize(tcpudpconnector_lstate_t *ls, tunnel_t *selected_connector);
void      tcpudpconnectorLinestateDestroy(tcpudpconnector_lstate_t *ls);
void      tcpudpconnectorTunnelstateDestroy(tcpudpconnector_tstate_t *ts);
