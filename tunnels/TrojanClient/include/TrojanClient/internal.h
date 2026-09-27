#pragma once

#include "interface.h"
#include "structure.h"

void trojanclientLinestateInitialize(trojanclient_lstate_t *ls, line_t *l);
void trojanclientLinestateDestroy(trojanclient_lstate_t *ls);

void trojanclientTunnelstateDestroy(trojanclient_tstate_t *ts);
bool trojanclientApplyTargetContext(tunnel_t *t, line_t *l);
void trojanclientStartUdpCarrier(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls);
void trojanclientOnNextEstablished(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls);
void trojanclientCloseLine(tunnel_t *t, line_t *l, trojanclient_close_origin_t origin);

bool trojanclientAssociationAlive(tunnel_t *t, line_t *next_line, line_t *prev_line);
void trojanclientSendDueRequest(tunnel_t *t, line_t *l);
void trojanclientCancelFirstPayloadTimer(trojanclient_lstate_t *ls);
void trojanclientSetNextPaused(tunnel_t *t, line_t *l, bool paused);

void trojanclientSetPrevPaused(tunnel_t *t, line_t *l, bool paused);

/* Shared implementation helpers; callbacks retain their directional admission. */
bool    trojanclientSendInitialRequest(tunnel_t *t, line_t *l, trojanclient_lstate_t *ls, sbuf_t *body);
bool    trojanclientWrapUdpPayload(line_t *l, sbuf_t **buf_io, const address_context_t *target);
int     trojanclientReadUdpHeader(trojanclient_lstate_t *ls);
sbuf_t *trojanclientExtractUdpBody(trojanclient_lstate_t *ls);
