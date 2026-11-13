#pragma once

#include "wwapi.h"

WW_EXPORT node_t    nodeConnectionStripeServerGet(void);
WW_EXPORT tunnel_t *connectionstripeserverTunnelCreate(node_t *node);

void connectionstripeserverTunnelUpStreamInit(tunnel_t *t, line_t *line);
void connectionstripeserverTunnelUpStreamEst(tunnel_t *t, line_t *line);
void connectionstripeserverTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void connectionstripeserverTunnelUpStreamPause(tunnel_t *t, line_t *line);
void connectionstripeserverTunnelUpStreamResume(tunnel_t *t, line_t *line);
void connectionstripeserverTunnelUpStreamFinish(tunnel_t *t, line_t *line);
void connectionstripeserverTunnelDownStreamEst(tunnel_t *t, line_t *line);
void connectionstripeserverTunnelDownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void connectionstripeserverTunnelDownStreamPause(tunnel_t *t, line_t *line);
void connectionstripeserverTunnelDownStreamResume(tunnel_t *t, line_t *line);
void connectionstripeserverTunnelDownStreamFinish(tunnel_t *t, line_t *line);
