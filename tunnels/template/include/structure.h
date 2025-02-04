#pragma once

#include "interface.h"
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
    kLineStateSize = sizeof(template_lstate_t)
};

WW_EXPORT void         templateTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *templateTunnelCreate(node_t *node);
WW_EXPORT api_result_t templateTunnelApi(tunnel_t *instance, sbuf_t *message);

WW_EXPORT void templateTunnelOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
WW_EXPORT void templateTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
WW_EXPORT void templateTunnelOnPrepair(tunnel_t *t);
WW_EXPORT void templateTunnelOnStart(tunnel_t *t);


WW_EXPORT void templateTunnelUpStreamInit(tunnel_t *t, line_t *l);
WW_EXPORT void templateTunnelUpStreamEst(tunnel_t *t, line_t *l);
WW_EXPORT void templateTunnelUpStreamFinish(tunnel_t *t, line_t *l);
WW_EXPORT void templateTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
WW_EXPORT void templateTunnelUpStreamPause(tunnel_t *t, line_t *l);
WW_EXPORT void templateTunnelUpStreamResume(tunnel_t *t, line_t *l);

WW_EXPORT void templateTunnelDownStreamInit(tunnel_t *t, line_t *l);
WW_EXPORT void templateTunnelDownStreamEst(tunnel_t *t, line_t *l);
WW_EXPORT void templateTunnelDownStreamFinish(tunnel_t *t, line_t *l);
WW_EXPORT void templateTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
WW_EXPORT void templateTunnelDownStreamPause(tunnel_t *t, line_t *l);
WW_EXPORT void templateTunnelDownStreamResume(tunnel_t *t, line_t *l);


void lineStateInitialize(template_lstate_t * ls);
void lineStateDestroy(template_lstate_t *ls);

