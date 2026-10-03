#pragma once

#include "splice_stream.h"
#include "wwapi.h"

typedef struct udpovertcpserver_tstate_s
{
    int unused;
} udpovertcpserver_tstate_t;

typedef struct udpovertcpserver_lstate_s
{
    splice_stream_t *read_stream;
    buffer_pool_t   *pool;
    bool             read_draining;
} udpovertcpserver_lstate_t;

enum
{
    kTunnelStateSize = sizeof(udpovertcpserver_tstate_t),
    kLineStateSize   = sizeof(udpovertcpserver_lstate_t),
    kHeaderSize      = 2, // 2 bytes for the length of the packet
    kMaxAllowedUDPPacketLength =
        65535 - 20 - 8 - kHeaderSize, // Maximum UDP packet size (shared with udp_over_tcp_client)
    kReadOverflowLimit = kMaxAllowedUDPPacketLength * 2,
    kReadChargeLimit   = 4U * 1024U * 1024U,
    kMaxReentryBytes   = 2U * 1024U * 1024U,
};

WW_EXPORT tunnel_t    *udpovertcpserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t udpovertcpserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void udpovertcpserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void udpovertcpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void udpovertcpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void udpovertcpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void udpovertcpserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void udpovertcpserverCloseLine(tunnel_t *t, line_t *l);

void udpovertcpserverLinestateInitialize(udpovertcpserver_lstate_t *ls, buffer_pool_t *pool);
void udpovertcpserverLinestateDestroy(udpovertcpserver_lstate_t *ls);
