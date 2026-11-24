#pragma once

#include "wwapi.h"

WW_EXPORT node_t nodeWireGuardClientGet(void);

tunnel_t *wireguardclientTunnelCreate(node_t *node);
void      wireguardclientTunnelOnStart(tunnel_t *t);
void      wireguardclientTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void      wireguardclientTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void      wireguardclientTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void      wireguardclientTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);

void wireguardclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *packet);
void wireguardclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void wireguardclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *packet);
void wireguardclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void wireguardclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void wireguardclientTunnelDownStreamResume(tunnel_t *t, line_t *l);
