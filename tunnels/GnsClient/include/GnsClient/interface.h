#pragma once

#include "wwapi.h"

WW_EXPORT node_t    nodeGnsClientGet(void);
WW_EXPORT tunnel_t *gnsclientTunnelCreate(node_t *node);

void gnsclientTunnelUpStreamInit(tunnel_t *t, line_t *line);
void gnsclientTunnelUpStreamEst(tunnel_t *t, line_t *line);
void gnsclientTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void gnsclientTunnelUpStreamPause(tunnel_t *t, line_t *line);
void gnsclientTunnelUpStreamResume(tunnel_t *t, line_t *line);
void gnsclientTunnelUpStreamFinish(tunnel_t *t, line_t *line);
void gnsclientTunnelDownStreamEst(tunnel_t *t, line_t *line);
void gnsclientTunnelDownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void gnsclientTunnelDownStreamPause(tunnel_t *t, line_t *line);
void gnsclientTunnelDownStreamResume(tunnel_t *t, line_t *line);
void gnsclientTunnelDownStreamFinish(tunnel_t *t, line_t *line);
