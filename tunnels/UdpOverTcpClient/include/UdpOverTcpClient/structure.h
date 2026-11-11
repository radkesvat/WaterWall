#pragma once

#include "wwapi.h"

typedef struct udpovertcpclient_lstate_s
{
    splice_frame_reader_t reader;
    log_rate_limiter_t    size_drop_log;
    size_t                last_rejected_bytes;
} udpovertcpclient_lstate_t;

enum
{
    kHeaderSize      = 2, // 2 bytes for the length of the packet
    kMaxAllowedUDPPacketLength =
        65535 - 20 - 8 - kHeaderSize, // Maximum UDP packet size (shared with udp_over_tcp_server)
    kReadChargeLimit   = 4U * 1024U * 1024U,
    kMaxReentryBytes   = 2U * 1024U * 1024U,
};

WW_EXPORT tunnel_t    *udpovertcpclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t udpovertcpclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void udpovertcpclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void udpovertcpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void udpovertcpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void udpovertcpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void udpovertcpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);

void udpovertcpclientCloseLine(tunnel_t *t, line_t *l);

void udpovertcpclientLinestateInitialize(udpovertcpclient_lstate_t *ls, buffer_pool_t *pool, bool splice_output);
void udpovertcpclientLinestateDestroy(udpovertcpclient_lstate_t *ls);
void udpovertcpclientLogSizeDrop(udpovertcpclient_lstate_t *ls, size_t length);
