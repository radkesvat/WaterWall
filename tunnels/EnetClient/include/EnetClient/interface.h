#pragma once

#include "wwapi.h"

WW_EXPORT node_t    nodeEnetClientGet(void);
WW_EXPORT tunnel_t *enetclientTunnelCreate(node_t *node);

void enetclientTunnelUpStreamInit(tunnel_t *t, line_t *line);
void enetclientTunnelUpStreamEst(tunnel_t *t, line_t *line);
void enetclientTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void enetclientTunnelUpStreamPause(tunnel_t *t, line_t *line);
void enetclientTunnelUpStreamResume(tunnel_t *t, line_t *line);
void enetclientTunnelUpStreamFinish(tunnel_t *t, line_t *line);
void enetclientTunnelDownStreamEst(tunnel_t *t, line_t *line);
void enetclientTunnelDownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void enetclientTunnelDownStreamPause(tunnel_t *t, line_t *line);
void enetclientTunnelDownStreamResume(tunnel_t *t, line_t *line);
void enetclientTunnelDownStreamFinish(tunnel_t *t, line_t *line);
