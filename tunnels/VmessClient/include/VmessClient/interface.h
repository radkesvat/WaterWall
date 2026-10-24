#pragma once

#include "wwapi.h"

WW_EXPORT node_t nodeVmessClientGet(void);

WW_EXPORT void         vmessclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *vmessclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t vmessclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void vmessclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);

void vmessclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void vmessclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void vmessclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void vmessclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void vmessclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void vmessclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void vmessclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void vmessclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void vmessclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void vmessclientTunnelDownStreamResume(tunnel_t *t, line_t *l);
bool vmessclientDomainResolverPrepare(tunnel_t *resolver, tunnel_t *client, line_t *l, void *user_lstate);
