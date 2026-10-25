#pragma once

#include "interface.h"
#include "structure.h"

void vmessserverLinestateInitialize(vmessserver_lstate_t *ls, tunnel_t *t, line_t *l, vmessserver_line_kind_t kind);
void vmessserverLinestateDestroy(vmessserver_lstate_t *ls);
void vmessserverTunnelstateDestroy(vmessserver_tstate_t *ts);

bool vmessserverDrainInput(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls);
void vmessserverCloseLineFromUpstream(tunnel_t *t, line_t *l);
void vmessserverCloseLineFromDownstream(tunnel_t *t, line_t *l);
void vmessserverCloseLineBidirectional(tunnel_t *t, line_t *l);
bool vmessserverForwardResponse(tunnel_t *t, line_t *l, sbuf_t *buf);
bool vmessserverDrainResponse(tunnel_t *t, line_t *l, bool admitted);
void vmessserverOnSelectedEstablished(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls);
bool vmessserverSendFallbackPayload(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls, sbuf_t *buf);
bool vmessserverScheduleFallbackPayloadDrain(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls);

bool vmessserverGatherHeader(vmessserver_lstate_t *ls, uint16_t needed);
void vmessserverRetainActiveHead(vmessserver_lstate_t *ls);
bool vmessserverStartFallback(tunnel_t *t, line_t *l);
void vmessserverCloseFallbackFromUpstream(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls, tunnel_t *fallback);

void vmessserverSetUdpBackendPaused(tunnel_t *t, line_t *remote_l, bool paused);
bool vmessserverLineAuthenticated(const vmessserver_lstate_t *ls);
void vmessserverRecordLineUser(line_t *l, vmessserver_lstate_t *ls);
void vmessserverApplyDestinationContext(line_t *l, const address_context_t *target, bool udp);
void vmessserverReconcileUdpSourcePermission(tunnel_t *t, line_t *client_l);
bool vmessserverStartUdpBranch(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls, const address_context_t *target);
bool vmessserverHandleInitialRequest(tunnel_t *t, line_t *l, vmessserver_lstate_t *ls);

/* The carrier is borrowed normal; UDP backend lines are owned normal. */
void        vmessserverProcessInput(tunnel_t *t, line_t *line);
bool        vmessserverDeliverDecoded(tunnel_t *t, line_t *line, sbuf_t *payload);
bool        vmessserverSendTermination(tunnel_t *t, line_t *line);
bool        vmessserverRegisterApi(tunnel_t *t);
void        vmessserverReason(vmessserver_lstate_t *ls, vmessserver_reason_t reason);
void        vmessserverDrop(vmessserver_lstate_t *ls, vmessserver_reason_t reason);
const char *vmessserverReasonName(vmessserver_reason_t reason);
void        vmessserverCloseUdpRemoteLineInternal(tunnel_t *t, line_t *remote_l, bool close_next);
void        vmessserverNotifyUdpPermission(tunnel_t *t, line_t *client_l);
bool        vmessserverUdpMember(tunnel_t *t, const vmessserver_lstate_t *client, line_t *remote);
