#pragma once

#include "interface.h"
#include "structure.h"

void vlessserverLinestateInitialize(vlessserver_lstate_t *ls, tunnel_t *t, line_t *l, vlessserver_line_kind_t kind);
void vlessserverLinestateDestroy(vlessserver_lstate_t *ls);
void vlessserverTunnelstateDestroy(vlessserver_tstate_t *ts);

bool vlessserverDrainInput(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, bool reject_short_password);
void vlessserverCloseLineFromUpstream(tunnel_t *t, line_t *l);
void vlessserverCloseLineFromDownstream(tunnel_t *t, line_t *l);
void vlessserverCloseLineBidirectional(tunnel_t *t, line_t *l);
bool vlessserverForwardResponse(tunnel_t *t, line_t *l, sbuf_t *buf);
bool vlessserverDrainResponse(tunnel_t *t, line_t *l, bool admitted);
void vlessserverOnSelectedEstablished(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls);
bool vlessserverWrapUdpPayload(line_t *l, sbuf_t **buf_io);
bool vlessserverSendFallbackPayload(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, sbuf_t *buf);
bool vlessserverScheduleFallbackPayloadDrain(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls);

bool    vlessserverGatherHeader(vlessserver_lstate_t *ls, uint16_t needed);
bool    vlessserverRetainActiveHead(vlessserver_lstate_t *ls);
sbuf_t *vlessserverExtractUdpBody(vlessserver_lstate_t *ls, uint16_t bytes);
bool    vlessserverStartFallback(tunnel_t *t, line_t *l);
void    vlessserverCloseFallbackFromUpstream(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, tunnel_t *fallback);

void                      vlessserverSetUdpBackendPaused(tunnel_t *t, line_t *remote_l, bool paused);
vlessserver_auth_result_t vlessserverAuthenticateUuid(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls,
                                                      const uint8_t uuid[kVlessServerUuidLen]);
bool                      vlessserverLineAuthenticated(const vlessserver_lstate_t *ls);
void                      vlessserverRecordLineUser(line_t *l, vlessserver_lstate_t *ls);
void                      vlessserverApplyDestinationContext(line_t *l, const address_context_t *target, bool udp);
void                      vlessserverReconcileUdpSourcePermission(tunnel_t *t, line_t *client_l);
bool vlessserverStartUdpBranch(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, const address_context_t *target);
bool vlessserverHandleInitialRequest(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls, bool reject_short_password);
bool vlessserverDrainUdpPackets(tunnel_t *t, line_t *l, vlessserver_lstate_t *ls);
