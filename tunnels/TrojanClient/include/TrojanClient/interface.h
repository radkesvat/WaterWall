#pragma once

#include "wwapi.h"

WW_EXPORT node_t nodeTrojanClientGet(void);

WW_EXPORT void         trojanclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT tunnel_t    *trojanclientTunnelCreate(node_t *node);
WW_EXPORT api_result_t trojanclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void trojanclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);

void trojanclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void trojanclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void trojanclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void trojanclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void trojanclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void trojanclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void trojanclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void trojanclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void trojanclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void trojanclientTunnelDownStreamResume(tunnel_t *t, line_t *l);
bool trojanclientDomainResolverPrepare(tunnel_t *resolver, tunnel_t *client, line_t *l, void *user_lstate);
