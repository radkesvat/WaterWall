#pragma once

#include "wwapi.h"

typedef struct blackhole_tstate_s
{
    uint8_t mode;
} blackhole_tstate_t;

typedef struct blackhole_lstate_s
{
    uint8_t unused;
} blackhole_lstate_t;

enum
{
    kTunnelStateSize = sizeof(blackhole_tstate_t),
    kLineStateSize   = sizeof(blackhole_lstate_t)
};

enum blackhole_mode_e
{
    kBlackHoleModePassive = 0,
    kBlackHoleModeActive  = 1
};

WW_EXPORT void         blackholeTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *blackholeTunnelCreate(node_t *node);
WW_EXPORT api_result_t blackholeTunnelApi(tunnel_t *instance, sbuf_t *message);

void blackholeTunnelUpStreamInit(tunnel_t *t, line_t *l);
void blackholeTunnelUpStreamEst(tunnel_t *t, line_t *l);
void blackholeTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void blackholeTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void blackholeTunnelUpStreamPause(tunnel_t *t, line_t *l);
void blackholeTunnelUpStreamResume(tunnel_t *t, line_t *l);

void blackholeTunnelDownStreamInit(tunnel_t *t, line_t *l);
void blackholeTunnelDownStreamEst(tunnel_t *t, line_t *l);
void blackholeTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void blackholeTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void blackholeTunnelDownStreamPause(tunnel_t *t, line_t *l);
void blackholeTunnelDownStreamResume(tunnel_t *t, line_t *l);

void blackholeLinestateInitialize(blackhole_lstate_t *ls);
void blackholeLinestateDestroy(blackhole_lstate_t *ls);
