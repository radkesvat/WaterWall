#pragma once

#include "wwapi.h"

WW_EXPORT node_t nodeWireGuardServerGet(void);

tunnel_t *wireguardserverTunnelCreate(node_t *node);
void      wireguardserverTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);
void      wireguardserverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void      wireguardserverTunnelOnPrepare(tunnel_t *t);
void      wireguardserverTunnelOnStart(tunnel_t *t);
void      wireguardserverTunnelOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void      wireguardserverTunnelOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void      wireguardserverTunnelOnWorkerStop(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);

void wireguardserverTunnelUpStreamInit(tunnel_t *t, line_t *line);
void wireguardserverTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *packet);
void wireguardserverTunnelUpStreamFinish(tunnel_t *t, line_t *line);
void wireguardserverTunnelUpStreamPause(tunnel_t *t, line_t *line);
void wireguardserverTunnelUpStreamResume(tunnel_t *t, line_t *line);
void wireguardserverTunnelDownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *packet);
void wireguardserverTunnelDownStreamFinish(tunnel_t *t, line_t *line);
