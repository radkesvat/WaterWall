#pragma once

#include "wwapi.h"

WW_EXPORT node_t nodeSynReplyGet(void);

tunnel_t *synreplyTunnelCreate(node_t *node);
void      synreplyTunnelUpStreamFinish(tunnel_t *t, line_t *line);
void      synreplyTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *payload);
void      synreplyTunnelDownStreamFinish(tunnel_t *t, line_t *line);
