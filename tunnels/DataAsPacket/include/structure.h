#pragma once

#include "wwapi.h"

typedef struct dataaspacket_tstate_s
{
    int unused;
} dataaspacket_tstate_t;

typedef struct dataaspacket_lstate_s
{
    line_t *line; // Pointer to the line associated with this state
    bool paused; // Indicates if the line is paused, dropping packets

} dataaspacket_lstate_t;

enum
{
    kTunnelStateSize = sizeof(dataaspacket_tstate_t),
    kLineStateSize   = sizeof(dataaspacket_lstate_t)
};

WW_EXPORT void         dataaspacketTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *dataaspacketTunnelCreate(node_t *node);
WW_EXPORT api_result_t dataaspacketTunnelApi(tunnel_t *instance, sbuf_t *message);

void dataaspacketTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void dataaspacketTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void dataaspacketTunnelOnPrepair(tunnel_t *t);
void dataaspacketTunnelOnStart(tunnel_t *t);

void dataaspacketTunnelUpStreamInit(tunnel_t *t, line_t *l);
void dataaspacketTunnelUpStreamEst(tunnel_t *t, line_t *l);
void dataaspacketTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void dataaspacketTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void dataaspacketTunnelUpStreamPause(tunnel_t *t, line_t *l);
void dataaspacketTunnelUpStreamResume(tunnel_t *t, line_t *l);

void dataaspacketTunnelDownStreamInit(tunnel_t *t, line_t *l);
void dataaspacketTunnelDownStreamEst(tunnel_t *t, line_t *l);
void dataaspacketTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void dataaspacketTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void dataaspacketTunnelDownStreamPause(tunnel_t *t, line_t *l);
void dataaspacketTunnelDownStreamResume(tunnel_t *t, line_t *l);

void dataaspacketLinestateInitialize(dataaspacket_lstate_t *ls);
void dataaspacketLinestateDestroy(dataaspacket_lstate_t *ls);
