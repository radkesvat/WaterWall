#pragma once

#include "wwapi.h"

WW_EXPORT node_t    nodeRtmpClientGet(void);
WW_EXPORT tunnel_t *rtmpclientTunnelCreate(node_t *node);

void rtmpclientTunnelUpStreamInit(tunnel_t *t, line_t *l);
void rtmpclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void rtmpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void rtmpclientTunnelUpStreamPause(tunnel_t *t, line_t *l);
void rtmpclientTunnelUpStreamResume(tunnel_t *t, line_t *l);

void rtmpclientTunnelDownStreamEst(tunnel_t *t, line_t *l);
void rtmpclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void rtmpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void rtmpclientTunnelDownStreamPause(tunnel_t *t, line_t *l);
void rtmpclientTunnelDownStreamResume(tunnel_t *t, line_t *l);
