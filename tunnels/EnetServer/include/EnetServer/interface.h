#pragma once

#include "wwapi.h"

WW_EXPORT node_t    nodeEnetServerGet(void);
WW_EXPORT tunnel_t *enetserverTunnelCreate(node_t *node);

void enetserverTunnelUpStreamInit(tunnel_t *t, line_t *line);
void enetserverTunnelUpStreamEst(tunnel_t *t, line_t *line);
void enetserverTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void enetserverTunnelUpStreamPause(tunnel_t *t, line_t *line);
void enetserverTunnelUpStreamResume(tunnel_t *t, line_t *line);
void enetserverTunnelUpStreamFinish(tunnel_t *t, line_t *line);
void enetserverTunnelDownStreamEst(tunnel_t *t, line_t *line);
void enetserverTunnelDownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void enetserverTunnelDownStreamPause(tunnel_t *t, line_t *line);
void enetserverTunnelDownStreamResume(tunnel_t *t, line_t *line);
void enetserverTunnelDownStreamFinish(tunnel_t *t, line_t *line);
