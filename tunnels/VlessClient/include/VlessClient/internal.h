#pragma once

#include "interface.h"
#include "structure.h"

void vlessclientLinestateInitialize(vlessclient_lstate_t *ls, line_t *l);
void vlessclientLinestateDestroy(vlessclient_lstate_t *ls);

void vlessclientTunnelstateDestroy(vlessclient_tstate_t *ts);
bool vlessclientApplyTargetContext(tunnel_t *t, line_t *l);
void vlessclientStartUdpCarrier(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls);
void vlessclientOnNextEstablished(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls);
void vlessclientCloseLine(tunnel_t *t, line_t *l, vlessclient_close_origin_t origin);

bool vlessclientAssociationAlive(tunnel_t *t, line_t *next_line, line_t *prev_line);
void vlessclientSendDueRequest(tunnel_t *t, line_t *l);
void vlessclientCancelFirstPayloadTimer(vlessclient_lstate_t *ls);
void vlessclientSetNextPaused(tunnel_t *t, line_t *l, bool paused);

void vlessclientSetPrevPaused(tunnel_t *t, line_t *l, bool paused);

/* Shared implementation helpers; callbacks retain their directional admission. */
bool    vlessclientSendInitialRequest(tunnel_t *t, line_t *l, vlessclient_lstate_t *ls, sbuf_t *body);
void    vlessclientWrapUdpPayload(line_t *l, sbuf_t **buf_io);
int     vlessclientReadUdpHeader(vlessclient_lstate_t *ls);
sbuf_t *vlessclientExtractUdpBody(vlessclient_lstate_t *ls);

int     vlessclientReadResponse(vlessclient_lstate_t *ls);
sbuf_t *vlessclientTakeTcpBody(vlessclient_lstate_t *ls);
