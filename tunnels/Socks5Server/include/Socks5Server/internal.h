#pragma once

/* Implementation-only helpers; the node interface remains interface.h. */
#include "address_codec.h"
#include "structure.h"

enum
{
    kSocks5Version               = 0x05,
    kSocks5NoAuthMethod          = 0x00,
    kSocks5UserPassMethod        = 0x02,
    kSocks5NoAcceptable          = 0xFF,
    kSocks5CommandConnect        = 0x01,
    kSocks5CommandBind           = 0x02,
    kSocks5CommandUdpAssoc       = 0x03,
    kSocks5AddrTypeIpv4          = 0x01,
    kSocks5AddrTypeDomain        = 0x03,
    kSocks5AddrTypeIpv6          = 0x04,
    kSocks5AuthVersion           = 0x01,
    kSocks5ReplySucceeded        = 0x00,
    kSocks5ReplyGeneralFailure   = 0x01,
    kSocks5ReplyCmdNotSupported  = 0x07,
    kSocks5ReplyAddrNotSupported = 0x08
};

void socks5serverLinestateInitialize(socks5server_lstate_t *ls, tunnel_t *t, line_t *l, socks5server_line_kind_t kind);
void socks5serverLinestateDestroy(socks5server_lstate_t *ls);

void socks5serverTunnelstateDestroy(socks5server_tstate_t *ts);
bool socks5serverResolveDynamicProvider(tunnel_t *t);
bool socks5serverControlDrainInput(tunnel_t *t, line_t *l, socks5server_lstate_t *ls);
void socks5serverOnControlEstablished(tunnel_t *t, line_t *l, socks5server_lstate_t *ls);
void socks5serverCloseControlLineFromUpstream(tunnel_t *t, line_t *l);
void socks5serverCloseControlLineFromDownstream(tunnel_t *t, line_t *l);
void socks5serverCloseControlLineBidirectional(tunnel_t *t, line_t *l);
void socks5serverCloseUdpClientLineFromUpstream(tunnel_t *t, line_t *client_l);
void socks5serverCloseUdpClientLine(tunnel_t *t, line_t *client_l);
void socks5serverCloseUdpRemoteLine(tunnel_t *t, line_t *remote_l);
bool socks5serverHandleUdpClientPayload(tunnel_t *t, line_t *l, socks5server_lstate_t *ls, sbuf_t *buf);
bool socks5serverWrapUdpPayloadForClient(line_t *l, sbuf_t **buf_io, const address_context_t *addr_ctx);
socks5server_assoc_entry_t *socks5serverFindWorkerAssociation(tunnel_t *t, wid_t wid, uint64_t generation);
bool    socks5serverAssociationIsActive(tunnel_t *t, wid_t wid, udplistener_dynamic_endpoint_handle_t handle,
                                        uint16_t assigned_port, socks5server_assoc_entry_t **entry_out);
bool    socks5serverValidateUdpClientAssociation(tunnel_t *t, line_t *l, socks5server_lstate_t *ls,
                                                 bool validate_provider_metadata);
void    socks5serverRejectUdpClientLine(tunnel_t *t, line_t *client_l);
void    socks5serverDetachRemoteFromClient(socks5server_lstate_t *remote_ls);
void    socks5serverUnregisterUdpAssociation(tunnel_t *t, socks5server_lstate_t *ls);
sbuf_t *socks5serverCreateCommandReply(line_t *l, uint8_t rep, const address_context_t *ctx);
void    socks5serverAssocEntryFreeCreds(socks5server_assoc_entry_t *entry);
void    socks5serverRecordLineUser(line_t *l, socks5server_lstate_t *ls, const user_handle_t *user_handle);
void    socks5serverRequireCurrentLineWorker(const line_t *l, const char *callback_name);

bool socks5serverDrainControl(tunnel_t *t, line_t *l);
bool socks5serverQueueControl(tunnel_t *t, line_t *l, sbuf_t *buf, bool upstream);

sbuf_t                 *socks5serverAllocBuffer(line_t *l, uint32_t len);
sbuf_t                 *socks5serverCreateMethodReply(line_t *l, uint8_t method);
sbuf_t                 *socks5serverCreateAuthReply(line_t *l, uint8_t status);
socks5_address_result_t socks5serverParseAddressBytes(const uint8_t *buf, size_t len, address_context_t *out,
                                                      size_t *consumed);
void                    socks5serverApplyDestinationContext(line_t *l, const address_context_t *target, bool udp);
void     socks5serverLogAuthRejected(tunnel_t *t, line_t *l, const uint8_t *username, uint8_t username_len,
                                     const char *reason);
bool     socks5serverAuthUserFromClient(tunnel_t *t, line_t *l, const uint8_t *username, uint8_t username_len,
                                        const uint8_t *password, uint8_t password_len, user_handle_t *user_handle_out);
bool     socks5serverStoreAuthCredentials(socks5server_lstate_t *ls, const uint8_t *username, uint8_t username_len,
                                          const uint8_t *password, uint8_t password_len);
uint16_t socks5serverGetLocalPort(const line_t *l);
bool     socks5serverRegisterUdpAssociation(tunnel_t *t, line_t *l, const user_handle_t *user_handle,
                                            const address_context_t *udp_peer_hint, uint16_t *assigned_port_out);
void     socks5serverCloseControlLine(tunnel_t *t, line_t *l, socks5server_close_origin_t origin, int reply_code,
                                      sbuf_t *final_reply);

void socks5serverAddressToContext(const socks5_address_t *value, address_context_t *out);
