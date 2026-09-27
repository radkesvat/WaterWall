#pragma once
#include "interface.h"
#include "structure.h"

bool     hpcParseSettings(hpc_tstate_t *ts, node_t *node);
bool     hpcBuildRequest(tunnel_t *t, line_t *l);
sbuf_t  *hpcBuffer(line_t *l, size_t n);
uint64_t hpcNow(line_t *l);
bool     hpcAllowed(tunnel_t *t, line_t *l);
void     hpcDetachTimer(hpc_lstate_t *ls);
bool     hpcStartTimer(tunnel_t *t, line_t *l);
void     hpcReleaseResponseStorage(hpc_lstate_t *ls);
void     hpcDestroyState(tunnel_t *t, line_t *l);
void     hpcClose(tunnel_t *t, line_t *l);
bool     hpcPressure(tunnel_t *t, line_t *l);
bool     hpcSendHeader(tunnel_t *t, line_t *l);
bool     hpcDrainUpload(tunnel_t *t, line_t *l);
bool     hpcDrainResponse(tunnel_t *t, line_t *l);
bool     hpcUpload(tunnel_t *t, line_t *l, sbuf_t *b);
bool     hpcResponse(tunnel_t *t, line_t *l, sbuf_t *b);
bool     hpcQueue(tunnel_t *t, line_t *l, sbuf_t *b, unsigned direction);
