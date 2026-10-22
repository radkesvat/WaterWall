#pragma once

#include "wwapi.h"

WW_EXPORT node_t       nodeQuicClientGet(void);
WW_EXPORT tunnel_t    *quicclientTunnelCreate(node_t *node);
WW_EXPORT void         quicclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
WW_EXPORT api_result_t quicclientTunnelApi(tunnel_t *instance, sbuf_t *message);

void quicclientTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void quicclientTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);

void quicclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void quicclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void quicclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void quicclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void quicclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void quicclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void quicclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void quicclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void quicclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void quicclientTunnelDownStreamResume(tunnel_t *t, line_t *l);
