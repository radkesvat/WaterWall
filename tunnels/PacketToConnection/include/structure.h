#pragma once

#include "wwapi.h"

typedef struct ptc_tstate_s
{
    struct netif netif;
} ptc_tstate_t;

typedef struct ptc_lstate_s
{
    int xxx;
} ptc_lstate_t;

enum
{
    kTunnelStateSize = sizeof(ptc_tstate_t),
    kLineStateSize   = sizeof(ptc_lstate_t)
};

WW_EXPORT void         ptcTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *ptcTunnelCreate(node_t *node);
WW_EXPORT api_result_t ptcTunnelApi(tunnel_t *instance, sbuf_t *message);

void ptcTunnelOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
void ptcTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void ptcTunnelOnPrepair(tunnel_t *t);
void ptcTunnelOnStart(tunnel_t *t);

void ptcTunnelUpStreamInit(tunnel_t *t, line_t *l);
void ptcTunnelUpStreamEst(tunnel_t *t, line_t *l);
void ptcTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void ptcTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void ptcTunnelUpStreamPause(tunnel_t *t, line_t *l);
void ptcTunnelUpStreamResume(tunnel_t *t, line_t *l);

void ptcTunnelDownStreamInit(tunnel_t *t, line_t *l);
void ptcTunnelDownStreamEst(tunnel_t *t, line_t *l);
void ptcTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void ptcTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void ptcTunnelDownStreamPause(tunnel_t *t, line_t *l);
void ptcTunnelDownStreamResume(tunnel_t *t, line_t *l);

void ptcLinestateInitialize(ptc_lstate_t *ls);
void ptcLinestateDestroy(ptc_lstate_t *ls);
