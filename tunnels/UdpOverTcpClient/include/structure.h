#pragma once

#include "wwapi.h"

typedef struct udpovertcpclient_tstate_s
{
    int unused;
} udpovertcpclient_tstate_t;

typedef struct udpovertcpclient_lstate_s
{
    int unused;
} udpovertcpclient_lstate_t;

enum
{
    kTunnelStateSize = sizeof(udpovertcpclient_tstate_t),
    kLineStateSize   = sizeof(udpovertcpclient_lstate_t),
    kMaxAllowedPacketLength = 65535 - 20 - 8, // Maximum UDP packet size
};

WW_EXPORT void         udpovertcpclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *udpovertcpclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t udpovertcpclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void udpovertcpclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void udpovertcpclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void udpovertcpclientTunnelOnPrepair(tunnel_t *t);
void udpovertcpclientTunnelOnStart(tunnel_t *t);

void udpovertcpclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void udpovertcpclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void udpovertcpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void udpovertcpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void udpovertcpclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void udpovertcpclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void udpovertcpclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void udpovertcpclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void udpovertcpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void udpovertcpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void udpovertcpclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void udpovertcpclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void udpovertcpclientLinestateInitialize(udpovertcpclient_lstate_t *ls);
void udpovertcpclientLinestateDestroy(udpovertcpclient_lstate_t *ls);
