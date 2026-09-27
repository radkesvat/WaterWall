#pragma once
#include "wwapi.h"

WW_EXPORT node_t nodeHttpProxyServerGet(void);

WW_EXPORT tunnel_t    *httpproxyserverTunnelCreate(node_t *node);
WW_EXPORT api_result_t httpproxyserverTunnelApi(tunnel_t *t, sbuf_t *message);
void                   httpproxyserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
void                   httpproxyserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void                   httpproxyserverTunnelOnPrepair(tunnel_t *t);
void httpproxyserverTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void httpproxyserverTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void httpproxyserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void httpproxyserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void httpproxyserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpproxyserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void httpproxyserverTunnelUpStreamResume(tunnel_t *t, line_t *l);
void httpproxyserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void httpproxyserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void httpproxyserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void httpproxyserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void httpproxyserverTunnelDownStreamResume(tunnel_t *t, line_t *l);
