#pragma once

#include "wwapi.h"

WW_EXPORT node_t nodeVmessServerGet(void);

WW_EXPORT void         vmessserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *vmessserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t vmessserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void vmessserverTunnelOnPrepair(tunnel_t *t);
void vmessserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);

void vmessserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void vmessserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void vmessserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void vmessserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void vmessserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void vmessserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void vmessserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void vmessserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void vmessserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void vmessserverTunnelDownStreamResume(tunnel_t *t, line_t *l);
