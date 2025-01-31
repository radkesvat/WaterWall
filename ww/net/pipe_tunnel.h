#pragma once
#include "tunnel.h"
#include "shiftbuffer.h"




size_t pipeLineGetMesageSize(void);

void pipetunnelDefaultUpStreamInit(tunnel_t *self, line_t *line);
void pipetunnelDefaultUpStreamEst(tunnel_t *self, line_t *line);
void pipetunnelDefaultUpStreamFin(tunnel_t *self, line_t *line);
void pipetunnelDefaultUpStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload);
void pipetunnelDefaultUpStreamPause(tunnel_t *self, line_t *line);
void pipetunnelDefaultUpStreamResume(tunnel_t *self, line_t *line);
void pipetunnelDefaultdownStreamInit(tunnel_t *self, line_t *line);
void pipetunnelDefaultdownStreamEst(tunnel_t *self, line_t *line);
void pipetunnelDefaultdownStreamFin(tunnel_t *self, line_t *line);
void pipetunnelDefaultdownStreamPayload(tunnel_t *self, line_t *line, sbuf_t *payload);
void pipetunnelDefaultDownStreamPause(tunnel_t *self, line_t *line);
void pipetunnelDefaultDownStreamResume(tunnel_t *self, line_t *line);
void pipetunnelDefaultOnChain(tunnel_t *t, tunnel_chain_t *tc);
void pipetunnelDefaultOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
void pipetunnelDefaultOnPrepair(tunnel_t *t);
void pipetunnelDefaultOnStart(tunnel_t *t);

tunnel_t *pipetunnelCreate(tunnel_t *child);
void      pipetunnelDestroy(tunnel_t *t);

void pipeTo(tunnel_t *t, line_t* l,wid_t wid_to);
