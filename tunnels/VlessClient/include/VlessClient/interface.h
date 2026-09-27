#pragma once

#include "wwapi.h"

WW_EXPORT node_t nodeVlessClientGet(void);

WW_EXPORT void         vlessclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *vlessclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t vlessclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void vlessclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);

void vlessclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void vlessclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void vlessclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void vlessclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void vlessclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void vlessclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void vlessclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void vlessclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void vlessclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void vlessclientTunnelDownStreamResume(tunnel_t *t, line_t *l);
bool vlessclientDomainResolverPrepare(tunnel_t *resolver, tunnel_t *client, line_t *l, void *user_lstate);
