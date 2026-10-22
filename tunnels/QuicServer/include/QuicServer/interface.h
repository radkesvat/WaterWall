#pragma once

#include "wwapi.h"

WW_EXPORT node_t       nodeQuicServerGet(void);
WW_EXPORT tunnel_t    *quicserverTunnelCreate(node_t *node);
WW_EXPORT void         quicserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT api_result_t quicserverTunnelApi(tunnel_t *instance, sbuf_t *message);

void quicserverTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void quicserverTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);

void quicserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void quicserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void quicserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void quicserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void quicserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void quicserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void quicserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void quicserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void quicserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void quicserverTunnelDownStreamResume(tunnel_t *t, line_t *l);
