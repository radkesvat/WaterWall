#pragma once

#include "wwapi.h"

WW_EXPORT node_t    nodeRtmpServerGet(void);
WW_EXPORT tunnel_t *rtmpserverTunnelCreate(node_t *node);

void rtmpserverTunnelUpStreamInit(tunnel_t *t, line_t *l);
void rtmpserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void rtmpserverTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void rtmpserverTunnelUpStreamPause(tunnel_t *t, line_t *l);
void rtmpserverTunnelUpStreamResume(tunnel_t *t, line_t *l);

void rtmpserverTunnelDownStreamEst(tunnel_t *t, line_t *l);
void rtmpserverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void rtmpserverTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void rtmpserverTunnelDownStreamPause(tunnel_t *t, line_t *l);
void rtmpserverTunnelDownStreamResume(tunnel_t *t, line_t *l);
