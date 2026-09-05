#pragma once

#include "wwapi.h"

typedef struct udpovertcpclient_tstate_s
{
    int unused;
} udpovertcpclient_tstate_t;

typedef struct udpovertcpclient_lstate_s
{
    buffer_stream_t read_stream;
} udpovertcpclient_lstate_t;

enum
{
    kTunnelStateSize    = sizeof(udpovertcpclient_tstate_t),
    kLineStateSize      = sizeof(udpovertcpclient_lstate_t),
    kHeaderSize         = 2, // 2 bytes for the length of the packet
    kProtocolMarkerSize = kHeaderSize + 1,
    kMaxAllowedUDPPacketLength =
        65535 - 20 - 8 - kHeaderSize, // Maximum UDP packet size (shared with udp_over_tcp_server)
};

WW_EXPORT tunnel_t    *udpovertcpclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t udpovertcpclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void udpovertcpclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void udpovertcpclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void udpovertcpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void udpovertcpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void udpovertcpclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void udpovertcpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void udpovertcpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void udpovertcpclientLinestateInitialize(udpovertcpclient_lstate_t *ls, buffer_pool_t *pool);
void udpovertcpclientLinestateDestroy(udpovertcpclient_lstate_t *ls);
