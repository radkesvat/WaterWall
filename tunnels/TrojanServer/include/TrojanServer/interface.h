#pragma once

#include "wwapi.h"

WW_EXPORT node_t nodeTrojanServerGet(void);

WW_EXPORT void         trojanserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *trojanserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t trojanserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void trojanserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void trojanserverTunnelOnPrepair(tunnel_t *t);

void trojanserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void trojanserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void trojanserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void trojanserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void trojanserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void trojanserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void trojanserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void trojanserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void trojanserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void trojanserverTunnelDownStreamResume(tunnel_t *t, line_t *l);
