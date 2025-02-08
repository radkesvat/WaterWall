#pragma once

#include "wwapi.h"

typedef struct template_tstate_s
{
    int xxx;
} template_tstate_t;

typedef struct template_lstate_s
{
    int xxx;
} template_lstate_t;

enum
{
    kTunnelStateSize = sizeof(template_tstate_t),
    kLineStateSize   = sizeof(template_lstate_t)
};

WW_EXPORT void         templateTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *templateTunnelCreate(node_t *node);
WW_EXPORT api_result_t templateTunnelApi(tunnel_t *instance, sbuf_t *message);

void templateTunnelOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
void templateTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void templateTunnelOnPrepair(tunnel_t *t);
void templateTunnelOnStart(tunnel_t *t);

void templateTunnelUpStreamInit(tunnel_t *t, line_t *l);
void templateTunnelUpStreamEst(tunnel_t *t, line_t *l);
void templateTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void templateTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void templateTunnelUpStreamPause(tunnel_t *t, line_t *l);
void templateTunnelUpStreamResume(tunnel_t *t, line_t *l);

void templateTunnelDownStreamInit(tunnel_t *t, line_t *l);
void templateTunnelDownStreamEst(tunnel_t *t, line_t *l);
void templateTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void templateTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void templateTunnelDownStreamPause(tunnel_t *t, line_t *l);
void templateTunnelDownStreamResume(tunnel_t *t, line_t *l);

void templateLinestateInitialize(template_lstate_t *ls);
void templateLinestateDestroy(template_lstate_t *ls);
