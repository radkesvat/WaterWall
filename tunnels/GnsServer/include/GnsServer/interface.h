#pragma once

#include "wwapi.h"

WW_EXPORT node_t    nodeGnsServerGet(void);
WW_EXPORT tunnel_t *gnsserverTunnelCreate(node_t *node);

void gnsserverTunnelUpStreamInit(tunnel_t *t, line_t *line);
void gnsserverTunnelUpStreamEst(tunnel_t *t, line_t *line);
void gnsserverTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void gnsserverTunnelUpStreamPause(tunnel_t *t, line_t *line);
void gnsserverTunnelUpStreamResume(tunnel_t *t, line_t *line);
void gnsserverTunnelUpStreamFinish(tunnel_t *t, line_t *line);
void gnsserverTunnelDownStreamEst(tunnel_t *t, line_t *line);
void gnsserverTunnelDownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void gnsserverTunnelDownStreamPause(tunnel_t *t, line_t *line);
void gnsserverTunnelDownStreamResume(tunnel_t *t, line_t *line);
void gnsserverTunnelDownStreamFinish(tunnel_t *t, line_t *line);
