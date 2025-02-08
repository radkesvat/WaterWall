#pragma once
#include "tunnel.h"

tunnel_t *packettunnelCreate(node_t *node, uint16_t tstate_size, uint16_t lstate_size);

void packettunnelDefaultUpStreamInit(tunnel_t *self, line_t *line);
void packettunnelDefaultUpStreamEst(tunnel_t *self, line_t *line);
void packettunnelDefaultUpStreamFin(tunnel_t *self, line_t *line);
void packettunnelDefaultUpStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload);
void packettunnelDefaultUpStreamPause(tunnel_t *self, line_t *line);
void packettunnelDefaultUpStreamResume(tunnel_t *self, line_t *line);

void packettunnelDefaultdownStreamInit(tunnel_t *self, line_t *line);
void packettunnelDefaultdownStreamEst(tunnel_t *self, line_t *line);
void packettunnelDefaultdownStreamFinish(tunnel_t *self, line_t *line);
void packettunnelDefaultdownStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload);
void packettunnelDefaultDownStreamPause(tunnel_t *self, line_t *line);
void packettunnelDefaultDownStreamResume(tunnel_t *self, line_t *line);
