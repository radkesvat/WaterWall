#pragma once

#include "wwapi.h"

typedef struct packetasdata_tstate_s
{
    int unused;
} packetasdata_tstate_t;

typedef struct packetasdata_lstate_s
{
    line_t *line; // Pointer to the line associated with this state
    bool paused; // Indicates if the line is paused, dropping packets

} packetasdata_lstate_t;

enum
{
    kTunnelStateSize = sizeof(packetasdata_tstate_t),
    kLineStateSize   = sizeof(packetasdata_lstate_t)
};

WW_EXPORT void         packetasdataTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *packetasdataTunnelCreate(node_t *node);
WW_EXPORT api_result_t packetasdataTunnelApi(tunnel_t *instance, sbuf_t *message);

void packetasdataTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset);
void packetasdataTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void packetasdataTunnelOnPrepair(tunnel_t *t);
void packetasdataTunnelOnStart(tunnel_t *t);

void packetasdataTunnelUpStreamInit(tunnel_t *t, line_t *l);
void packetasdataTunnelUpStreamEst(tunnel_t *t, line_t *l);
void packetasdataTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void packetasdataTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void packetasdataTunnelUpStreamPause(tunnel_t *t, line_t *l);
void packetasdataTunnelUpStreamResume(tunnel_t *t, line_t *l);

void packetasdataTunnelDownStreamInit(tunnel_t *t, line_t *l);
void packetasdataTunnelDownStreamEst(tunnel_t *t, line_t *l);
void packetasdataTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void packetasdataTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void packetasdataTunnelDownStreamPause(tunnel_t *t, line_t *l);
void packetasdataTunnelDownStreamResume(tunnel_t *t, line_t *l);

void packetasdataLinestateInitialize(packetasdata_lstate_t *ls);
void packetasdataLinestateDestroy(packetasdata_lstate_t *ls);
