#pragma once
#include "wwapi.h"
WW_EXPORT node_t nodeHttpProxyClientGet(void);

WW_EXPORT tunnel_t    *httpproxyclientTunnelCreate(node_t *node);
WW_EXPORT void         httpproxyclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT api_result_t httpproxyclientTunnelApi(tunnel_t *t, sbuf_t *message);
void httpproxyclientTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void httpproxyclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void httpproxyclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *b);
void httpproxyclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void httpproxyclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void httpproxyclientTunnelUpStreamResume(tunnel_t *t, line_t *l);
void httpproxyclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void httpproxyclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *b);
void httpproxyclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void httpproxyclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void httpproxyclientTunnelDownStreamResume(tunnel_t *t, line_t *l);
void httpproxyclientTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
bool hpcDomainResolverPrepare(tunnel_t *resolver, tunnel_t *owner, line_t *l, void *user_lstate);
