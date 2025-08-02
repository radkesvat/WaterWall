#pragma once

#include "wwapi.h"

typedef struct udpovertcpserver_tstate_s
{
    int unused;
} udpovertcpserver_tstate_t;

typedef struct udpovertcpserver_lstate_s
{
    buffer_stream_t read_stream;
} udpovertcpserver_lstate_t;

enum
{
    kTunnelStateSize        = sizeof(udpovertcpserver_tstate_t),
    kLineStateSize          = sizeof(udpovertcpserver_lstate_t),
    kHeaderSize             = 2,                            // 2 bytes for the length of the packet
    kMaxAllowedPacketLength = 65535 - 20 - 8 - kHeaderSize, // Maximum UDP packet size (shared with udp_over_tcp_client)
};

WW_EXPORT void         udpovertcpserverTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *udpovertcpserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t udpovertcpserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void udpovertcpserverTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void udpovertcpserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void udpovertcpserverTunnelOnPrepair(tunnel_t *t);
void udpovertcpserverTunnelOnStart(tunnel_t *t);

void udpovertcpserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void udpovertcpserverTunnelUpStreamEst(tunnel_t *t, line_t *l);
void udpovertcpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void udpovertcpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void udpovertcpserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void udpovertcpserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void udpovertcpserverTunnelDownStreamInit(tunnel_t *t, line_t *l);
void udpovertcpserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void udpovertcpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void udpovertcpserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void udpovertcpserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void udpovertcpserverTunnelDownStreamResume(tunnel_t *t, line_t *l);

void udpovertcpserverLinestateInitialize(udpovertcpserver_lstate_t *ls, buffer_pool_t *pool);
void udpovertcpserverLinestateDestroy(udpovertcpserver_lstate_t *ls);
