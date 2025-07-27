#pragma once

#include "wwapi.h"

typedef struct tlsclient_tstate_s
{
    int unused;
} tlsclient_tstate_t;

typedef struct tlsclient_lstate_s
{
    int unused;
} tlsclient_lstate_t;

enum
{
    kTunnelStateSize = sizeof(tlsclient_tstate_t),
    kLineStateSize   = sizeof(tlsclient_lstate_t)
};

WW_EXPORT void         tlsclientTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *tlsclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t tlsclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void tlsclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void tlsclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void tlsclientTunnelOnPrepair(tunnel_t *t);
void tlsclientTunnelOnStart(tunnel_t *t);

void tlsclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void tlsclientTunnelUpStreamEst(tunnel_t *t, line_t *l);
void tlsclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void tlsclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tlsclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void tlsclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void tlsclientTunnelDownStreamInit(tunnel_t *t, line_t *l);
void tlsclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void tlsclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void tlsclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void tlsclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void tlsclientTunnelDownStreamResume(tunnel_t *t, line_t *l);

void tlsclientLinestateInitialize(tlsclient_lstate_t *ls);
void tlsclientLinestateDestroy(tlsclient_lstate_t *ls);
