#pragma once

#include "wwapi.h"

WW_EXPORT node_t    nodeConnectionStripeClientGet(void);
WW_EXPORT tunnel_t *connectionstripeclientTunnelCreate(node_t *node);

void connectionstripeclientTunnelUpStreamInit(tunnel_t *t, line_t *line);
void connectionstripeclientTunnelUpStreamEst(tunnel_t *t, line_t *line);
void connectionstripeclientTunnelUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void connectionstripeclientTunnelUpStreamPause(tunnel_t *t, line_t *line);
void connectionstripeclientTunnelUpStreamResume(tunnel_t *t, line_t *line);
void connectionstripeclientTunnelUpStreamFinish(tunnel_t *t, line_t *line);
void connectionstripeclientTunnelDownStreamEst(tunnel_t *t, line_t *line);
void connectionstripeclientTunnelDownStreamPayload(tunnel_t *t, line_t *line, sbuf_t *buf);
void connectionstripeclientTunnelDownStreamPause(tunnel_t *t, line_t *line);
void connectionstripeclientTunnelDownStreamResume(tunnel_t *t, line_t *line);
void connectionstripeclientTunnelDownStreamFinish(tunnel_t *t, line_t *line);
