#pragma once
#include "wireguard_endian_helpers.h"
#include "wireguard_types.h"
#include "wwapi.h"

/* Initialize before publication; all subsequent processing has one worker owner. */
bool wireguardCommonInit(wireguard_device_t *device, const char *private_key, void *context,
                         wireguard_callbacks_t callbacks);
/* Each input is consumed on all paths. No engine locks or neighbour callbacks
 * under locks: wrappers marshal processing to their designated event worker. */
void wireguardCommonReceive(wireguard_device_t *device, sbuf_t *packet, const ip_addr_t *source, uint16_t port);
/* A connected datagram carrier supplies its own routing, without a physical
 * source endpoint. Its nonzero identity must remain stable for that carrier and
 * change on replacement. Cookies bind to this identity; authenticated input does
 * not learn an IP/port. Output callbacks must route addressless cookie replies
 * (source NULL, port zero) through the same carrier. Input is always consumed. */
void              wireguardCommonReceiveOnCarrier(wireguard_device_t *device, sbuf_t *packet, uint64_t carrier_id);
void              wireguardCommonSendInner(wireguard_device_t *device, sbuf_t *packet);
wireguard_peer_t *wireguardCommonPeerForIp(wireguard_device_t *device, const ip_addr_t *ip);
bool              wireguardCommonPeerAllowsIp(const wireguard_peer_t *peer, const ip_addr_t *ip);
sbuf_t *wireguardCommonDecrypt(buffer_pool_t *pool, const uint8_t *ciphertext, uint32_t length, uint64_t nonce,
                               wireguard_keypair_t *keypair);
/* Static peer settings: publickey, allowedips, optional presharedkey and
 * persistentkeepalive. Endpoint ownership belongs to each public wrapper. */
bool wireguardCommonAddConfiguredPeer(wireguard_device_t *device, const cJSON *settings, uint8_t *index);
bool wireguardCommonRangesOverlap(const wireguard_allowed_ip_t *a, const wireguard_allowed_ip_t *b);

/***************************************** WireGuard Interface ****************************************** */

/* wireguard device cycle is the heart of the device that is by defalut runs every 400 ms*/
void wireguardCommonLoop(wireguard_device_t *device);

// Helper to initialise the peer struct with defaults
void wireguardifPeerInit(wireguard_peer_init_data_t *peer);

// Add a new peer to the specified interface - see wireguard.h for maximum number of peers allowed
// On success the peer_index can be used to reference this peer in future function calls
err_t wireguardifAddPeer(wireguard_device_t *device, wireguard_peer_init_data_t *peer, uint8_t *peer_index);
err_t wireguardifAddAllowedIp(wireguard_device_t *device, uint8_t peer_index, const ip_addr_t *ip,
                              const ip_addr_t *mask);

// Remove the given peer from the network interface
err_t wireguardifRemovePeer(wireguard_device_t *device, uint8_t peer_index);

// Stop trying to connect to the given peer
err_t wireguardifDisconnect(wireguard_device_t *device, uint8_t peer_index);

err_t wireguardifStartHandshake(wireguard_device_t *device, wireguard_peer_t *peer, bool force);
err_t wireguardifRetryHandshake(wireguard_device_t *device, wireguard_peer_t *peer);
err_t wireguardifPeerOutput(wireguard_device_t *device, sbuf_t *q, wireguard_peer_t *peer);
err_t wireguardifDeviceOutput(wireguard_device_t *device, sbuf_t *q, const ip_addr_t *ipaddr, uint16_t port);
void  wireguardifSendKeepalive(wireguard_device_t *device, wireguard_peer_t *peer);
err_t wireguardifOutputToPeer(wireguard_device_t *device, sbuf_t *q, const ip_addr_t *ipaddr, wireguard_peer_t *peer);

/***************************************** WireGuard Device ****************************************** */

WCRYPTO_MUST_USE wcrypto_status_t wireguardInit(void);
bool                              wireguardDeviceInit(wireguard_device_t *device, const uint8_t *private_key);
void                              wireguardDeviceDestroy(wireguard_device_t *device);
bool wireguardPeerInit(wireguard_device_t *device, wireguard_peer_t *peer, const uint8_t *public_key,
                       const uint8_t *preshared_key);

wireguard_peer_t *peerAlloc(wireguard_device_t *device);
uint8_t           wireguardPeerIndex(wireguard_device_t *device, wireguard_peer_t *peer);
wireguard_peer_t *peerLookupByPubkey(wireguard_device_t *device, uint8_t *public_key);
wireguard_peer_t *peerLookupByPeerIndex(wireguard_device_t *device, uint8_t peer_index);
wireguard_peer_t *peerLookupByReceiver(wireguard_device_t *device, uint32_t receiver);
wireguard_peer_t *peerLookupByHandshake(wireguard_device_t *device, uint32_t receiver);
wireguard_peer_t *peerLookupByPendingHandshake(wireguard_device_t *device, uint32_t receiver);

WCRYPTO_MUST_USE bool wireguardStartSession(wireguard_peer_t *peer, bool initiator);
void                  keypairUpdate(wireguard_peer_t *peer, wireguard_keypair_t *received_keypair);
void                  keypairDestroy(wireguard_keypair_t *keypair);

wireguard_keypair_t *getPeerKeypairForIdx(wireguard_peer_t *peer, uint32_t idx);
bool                 wireguardCheckReplay(wireguard_keypair_t *keypair, uint64_t seq);
uint8_t              wireguardGetMessageType(const uint8_t *data, size_t len);

wireguard_peer_t *wireguardProcessInitiationMessage(wireguard_device_t *device, message_handshake_initiation_t *msg);
bool              wireguardProcessHandshakeResponse(wireguard_device_t *device, wireguard_peer_t *peer,
                                                    message_handshake_response_t *src);
bool wireguardProcessCookieMessage(wireguard_device_t *device, wireguard_peer_t *peer, message_cookie_reply_t *src);
bool wireguardStorePendingHandshake(wireguard_peer_t *peer, const void *packet, size_t packet_len);
void wireguardClearPendingHandshake(wireguard_peer_t *peer);
void wireguardClearHandshakeState(wireguard_peer_t *peer);

bool wireguardCreateHandshakeInitiation(wireguard_device_t *device, wireguard_peer_t *peer,
                                        message_handshake_initiation_t *dst);
bool wireguardCreateHandshakeResponse(wireguard_device_t *device, wireguard_peer_t *peer,
                                      message_handshake_response_t *dst);
bool wireguardCreateCookieReply(wireguard_device_t *device, message_cookie_reply_t *dst, const uint8_t *mac1,
                                uint32_t index, uint8_t *source_addr_port, size_t source_length);

bool wireguardCheckMac1(wireguard_device_t *device, const uint8_t *data, size_t len, const uint8_t *mac1);
bool wireguardCheckMac2(wireguard_device_t *device, const uint8_t *data, size_t len, uint8_t *source_addr_port,
                        size_t source_length, const uint8_t *mac2);

bool wireguardExpired(uint32_t created_millis, uint32_t valid_seconds);

WCRYPTO_MUST_USE bool wireguardEncryptPacket(uint8_t *dst, size_t dst_capacity, const uint8_t *src, size_t src_len,
                                             wireguard_keypair_t *keypair);
WCRYPTO_MUST_USE bool wireguardDecryptPacket(uint8_t *dst, size_t dst_capacity, const uint8_t *src, size_t src_len,
                                             uint64_t counter, wireguard_keypair_t *keypair);
