#pragma once

/* Implementation-only helpers; node exports remain in interface.h. */
#include "structure.h"

enum
{
    kSocks5Version         = 0x05,
    kSocks5NoAuthMethod    = 0x00,
    kSocks5UserPassMethod  = 0x02,
    kSocks5NoAcceptable    = 0xFF,
    kSocks5CommandConnect  = 0x01,
    kSocks5CommandUdpAssoc = 0x03,
    kSocks5AddrTypeIpv4    = 0x01,
    kSocks5AddrTypeDomain  = 0x03,
    kSocks5AddrTypeIpv6    = 0x04,
    kSocks5AuthVersion     = 0x01
};

void socks5clientLinestateInitialize(socks5client_lstate_t *ls, tunnel_t *t, line_t *l, socks5client_line_kind_t kind);
void socks5clientLinestateDestroy(socks5client_lstate_t *ls);

void socks5clientTunnelstateDestroy(socks5client_tstate_t *ts);
bool socks5clientApplyTargetContext(tunnel_t *t, line_t *l);
bool socks5clientSendGreeting(tunnel_t *t, line_t *l, socks5client_lstate_t *ls);
bool socks5clientSendAuthRequest(tunnel_t *t, line_t *l, socks5client_lstate_t *ls);
bool socks5clientSendConnectRequest(tunnel_t *t, line_t *l, socks5client_lstate_t *ls);
bool socks5clientDrainHandshakeInput(tunnel_t *t, line_t *l, socks5client_lstate_t *ls);
bool socks5clientStartUdpAssociation(tunnel_t *t, line_t *l, socks5client_lstate_t *ls, bool *line_alive_out);
bool socks5clientForwardUdpApplicationPayload(tunnel_t *t, line_t *l, socks5client_lstate_t *ls, sbuf_t *buf);
bool socks5clientHandleUdpRelayPayload(tunnel_t *t, line_t *l, socks5client_lstate_t *ls, sbuf_t *buf);
void socks5clientOnUdpRelayEstablished(tunnel_t *t, line_t *l, socks5client_lstate_t *ls);
void socks5clientCloseOwnedLine(tunnel_t *t, line_t *owned_l);
void socks5clientCloseLineBidirectional(tunnel_t *t, line_t *l);

bool socks5clientDrainPending(tunnel_t *t, line_t *l);
bool socks5clientQueuePayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void socks5clientSetNextPaused(tunnel_t *t, line_t *l, bool paused);

bool socks5clientMaybeSendGreeting(tunnel_t *t, line_t *l);

bool socks5clientQueueReplyInput(tunnel_t *t, line_t *l, sbuf_t *buf);

sbuf_t *socks5clientAllocHandshakeBuffer(line_t *l, uint32_t len);
int     socks5clientParseAddressBytes(const uint8_t *buf, size_t len, address_context_t *out, size_t *consumed);
bool    socks5clientWrapUdpPayload(line_t *l, sbuf_t **buf_io, const address_context_t *target);
bool    socks5clientForwardUdpPayloadToRelay(tunnel_t *t, line_t *application_l, socks5client_lstate_t *application_ls,
                                             sbuf_t *buf);
bool socks5clientTryEstablishUdpApplication(tunnel_t *t, line_t *application_l, socks5client_lstate_t *application_ls);
bool socks5clientStartUdpRelayLine(tunnel_t *t, line_t *control_l, socks5client_lstate_t *control_ls,
                                   const address_context_t *relay_addr, bool *control_alive_out);
