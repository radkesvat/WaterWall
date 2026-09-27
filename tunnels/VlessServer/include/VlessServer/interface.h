#pragma once

#include "wwapi.h"

WW_EXPORT node_t nodeVlessServerGet(void);

WW_EXPORT void         vlessserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *vlessserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t vlessserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void vlessserverTunnelOnPrepair(tunnel_t *t);
void vlessserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);

void vlessserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void vlessserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void vlessserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void vlessserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void vlessserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void vlessserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void vlessserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void vlessserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void vlessserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void vlessserverTunnelDownStreamResume(tunnel_t *t, line_t *l);
