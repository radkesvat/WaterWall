#pragma once

#include "interface.h"
#include "structure.h"

void trojanserverLinestateInitialize(trojanserver_lstate_t *ls, tunnel_t *t, line_t *l, trojanserver_line_kind_t kind);
void trojanserverReleaseBuffers(trojanserver_lstate_t *ls);
void trojanserverLinestateDestroy(trojanserver_lstate_t *ls);
void trojanserverTunnelstateDestroy(trojanserver_tstate_t *ts);

void trojanserverPump(tunnel_t *t, line_t *l);
void trojanserverCloseLineFromUpstream(tunnel_t *t, line_t *l);
void trojanserverCloseLineFromDownstream(tunnel_t *t, line_t *l);
void trojanserverCloseLineBidirectional(tunnel_t *t, line_t *l);
void trojanserverOnNextEstablished(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls);
bool trojanserverWrapUdpPayload(line_t *l, sbuf_t **buf_io);
bool trojanserverSendFallbackPayload(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls, sbuf_t *buf);
bool trojanserverScheduleFallbackPayloadDrain(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls);

bool trojanserverIsUdp(const trojanserver_lstate_t *ls);
/* On success the queue owns *buf; on refusal the caller still owns it. */
bool trojanserverQueuePayload(buffer_queue_t *queue, sbuf_t **buf);

void trojanserverSetNextPaused(tunnel_t *t, line_t *l, bool paused);

/* Shared implementation helpers; callbacks retain their directional admission. */
bool trojanserverApplyDestinationContext(line_t *l, const trojanserver_address_t *target, bool udp);
trojanserver_auth_result_t trojanserverAuthenticateHash(tunnel_t *t, line_t *l,
                                                        const uint8_t  sha224[SHA224_DIGEST_SIZE],
                                                        user_handle_t *user_handle_out);
void      trojanserverRecordLineUser(line_t *l, trojanserver_lstate_t *ls, const user_handle_t *user_handle);
tunnel_t *trojanserverSelectedUpstream(tunnel_t *t, const trojanserver_lstate_t *ls);
void      trojanserverResetHeader(trojanserver_lstate_t *ls);
bool      trojanserverRetainActiveHead(trojanserver_lstate_t *ls);
void      trojanserverParseInitial(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls);
bool      trojanserverDecodeUdp(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls);
void      trojanserverCloseFallbackFromUpstream(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls, tunnel_t *fallback);
void      trojanserverStartFallback(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls);
void      trojanserverCloseUdpRemoteLineInternal(tunnel_t *t, line_t *remote_l, bool close_next);
void      trojanserverCloseUdpRemoteLines(tunnel_t *t, trojanserver_lstate_t *client);
line_t   *trojanserverGetOrCreateUdpRemoteLine(tunnel_t *t, line_t *client_l, trojanserver_lstate_t *client,
                                               const trojanserver_address_t *target);
bool      trojanserverNotifyRemotePermission(tunnel_t *t, line_t *l, trojanserver_lstate_t *ls);

bool trojanserverSetCredentialSnapshot(trojanserver_lstate_t *ls, const char *username, const char *password);
