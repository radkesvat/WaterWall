#pragma once

#include "wwapi.h"

typedef struct bridge_tstate_s
{
    node_t   *pair_node;
    tunnel_t *pair;
    bool      mode_upside; // if this node is last node of upstream
} bridge_tstate_t;

typedef struct bridge_lstate_s
{
    int unused;
} bridge_lstate_t;

enum
{
    kTunnelStateSize = sizeof(bridge_tstate_t),
    kLineStateSize   = sizeof(bridge_lstate_t)
};

WW_EXPORT void         bridgeTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *bridgeTunnelCreate(node_t *node);
WW_EXPORT api_result_t bridgeTunnelApi(tunnel_t *instance, sbuf_t *message);

void bridgeTunnelOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
void bridgeTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void bridgeTunnelOnPrepair(tunnel_t *t);
void bridgeTunnelOnStart(tunnel_t *t);

void bridgeTunnelUpStreamInit(tunnel_t *t, line_t *l);
void bridgeTunnelUpStreamEst(tunnel_t *t, line_t *l);
void bridgeTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void bridgeTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void bridgeTunnelUpStreamPause(tunnel_t *t, line_t *l);
void bridgeTunnelUpStreamResume(tunnel_t *t, line_t *l);

void bridgeTunnelDownStreamInit(tunnel_t *t, line_t *l);
void bridgeTunnelDownStreamEst(tunnel_t *t, line_t *l);
void bridgeTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void bridgeTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void bridgeTunnelDownStreamPause(tunnel_t *t, line_t *l);
void bridgeTunnelDownStreamResume(tunnel_t *t, line_t *l);

void bridgeLinestateInitialize(bridge_lstate_t *ls);
void bridgeLinestateDestroy(bridge_lstate_t *ls);
