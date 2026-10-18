#pragma once

#include "wwapi.h"

node_t    nodeAPIServerGet(void);
tunnel_t *apiserverTunnelCreate(node_t *node);

void apiserverOnPrepair(tunnel_t *t);
void apiserverOnQuiesceRequest(tunnel_t *t, const ww_lifecycle_context_t *context);
void apiserverOnWorkerQuiesce(tunnel_t *t, wid_t wid, const ww_lifecycle_context_t *context);
void apiserverDestroy(tunnel_t *t, const ww_lifecycle_context_t *context);

void apiserverUpStreamInit(tunnel_t *t, line_t *line);
void apiserverUpStreamPayload(tunnel_t *t, line_t *line, sbuf_t *payload);
void apiserverUpStreamFinish(tunnel_t *t, line_t *line);
void apiserverUpStreamPause(tunnel_t *t, line_t *line);
void apiserverUpStreamResume(tunnel_t *t, line_t *line);
