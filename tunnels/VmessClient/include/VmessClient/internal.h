#pragma once
#include "interface.h"
#include "structure.h"
void vmessclientLinestateInitialize(vmessclient_lstate_t *ls, line_t *l);
void vmessclientLinestateDestroy(vmessclient_lstate_t *ls);
void vmessclientTunnelstateDestroy(vmessclient_tstate_t *ts);
bool vmessclientApplyTargetContext(tunnel_t *t, line_t *l);
void vmessclientStartUdpCarrier(tunnel_t *t, line_t *l, vmessclient_lstate_t *ls);
void vmessclientOnNextEstablished(tunnel_t *t, line_t *l, vmessclient_lstate_t *ls);
void vmessclientCloseLine(tunnel_t *t, line_t *l, vmessclient_close_origin_t origin);
bool vmessclientAssociationAlive(tunnel_t *t, line_t *next_line, line_t *prev_line);
void vmessclientSendDueRequest(tunnel_t *t, line_t *l);
void vmessclientCancelFirstPayloadTimer(vmessclient_lstate_t *ls);
void vmessclientSetNextPaused(tunnel_t *t, line_t *l, bool paused);
bool vmessclientCommitRequest(vmessclient_lstate_t *ls, uint8_t *out, size_t capacity, size_t *written);
void vmessclientTransmit(tunnel_t *t, line_t *l);
void vmessclientReceive(tunnel_t *t, line_t *l);

sbuf_t *vmessclientCompactInput(line_t *l, sbuf_t *buf);
