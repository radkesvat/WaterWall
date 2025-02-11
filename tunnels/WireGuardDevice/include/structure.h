#pragma once

#include "wwapi.h"

#include "wireguard_endian_helpers.h"
#include "wireguard_types.h"

typedef struct wgd_tstate_s
{
    // this is th real wireguard device that we built using data
    // Note dont change the order of this struct, we use pointer casting to get the device and state
    wireguard_device_t wg_device;

    tunnel_t *tunnel;
    wmutex_t  mutex;
    
    // the data that came from json configuration, we build real wireguard device from this
    wireguard_device_init_data_t device_configuration;


} wgd_tstate_t;

typedef struct wgd_lstate_s
{
    int xxx;
} wgd_lstate_t;

enum
{
    kTunnelStateSize = sizeof(wgd_tstate_t),
    kLineStateSize   = sizeof(wgd_lstate_t)
};

WW_EXPORT void         wireguarddeviceTunnelDestroy(tunnel_t *t);
WW_EXPORT tunnel_t    *wireguarddeviceTunnelCreate(node_t *node);
WW_EXPORT api_result_t wireguarddeviceTunnelApi(tunnel_t *instance, sbuf_t *message);

void wireguarddeviceTunnelOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
void wireguarddeviceTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
void wireguarddeviceTunnelOnPrepair(tunnel_t *t);
void wireguarddeviceTunnelOnStart(tunnel_t *t);

void wireguarddeviceTunnelUpStreamInit(tunnel_t *t, line_t *l);
void wireguarddeviceTunnelUpStreamEst(tunnel_t *t, line_t *l);
void wireguarddeviceTunnelUpStreamFinish(tunnel_t *t, line_t *l);
void wireguarddeviceTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void wireguarddeviceTunnelUpStreamPause(tunnel_t *t, line_t *l);
void wireguarddeviceTunnelUpStreamResume(tunnel_t *t, line_t *l);

void wireguarddeviceTunnelDownStreamInit(tunnel_t *t, line_t *l);
void wireguarddeviceTunnelDownStreamEst(tunnel_t *t, line_t *l);
void wireguarddeviceTunnelDownStreamFinish(tunnel_t *t, line_t *l);
void wireguarddeviceTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
void wireguarddeviceTunnelDownStreamPause(tunnel_t *t, line_t *l);
void wireguarddeviceTunnelDownStreamResume(tunnel_t *t, line_t *l);

void wireguarddeviceLinestateInitialize(wgd_lstate_t *ls);
void wireguarddeviceLinestateDestroy(wgd_lstate_t *ls);

/***************************************** WireGuard Interface ****************************************** */

/* wireguard device cycle is the heart of the device that is by defalut runs every 400 ms*/
void wireguarddeviceLoop(wireguard_device_t *device);


// Helper to initialise the peer struct with defaults
void wireguardifPeerInit(wireguard_peer_init_data_t *peer);

// Add a new peer to the specified interface - see wireguard.h for maximum number of peers allowed
// On success the peer_index can be used to reference this peer in future function calls
err_t wireguardifAddPeer(wireguard_device_t *device, wireguard_peer_init_data_t *peer, uint8_t *peer_index);

// Remove the given peer from the network interface
err_t wireguardifRemovePeer(wireguard_device_t *device, uint8_t peer_index);

// Update the "connect" IP of the given peer
err_t wireguardifUpdateEndpoint(wireguard_device_t *device, uint8_t peer_index, const ip_addr_t *ip, uint16_t port);

// Try and connect to the given peer
err_t wireguardifConnect(wireguard_device_t *device, uint8_t peer_index);

// Stop trying to connect to the given peer
err_t wireguardifDisconnect(wireguard_device_t *device, uint8_t peer_index);

// Is the given peer "up"? A peer is up if it has a valid session key it can communicate with
err_t wireguardifPeerIsUp(wireguard_device_t *device, uint8_t peer_index, ip_addr_t *current_ip,
                          uint16_t *current_port);

err_t wireguardifPeerOutput(wireguard_device_t *device, sbuf_t *q, wireguard_peer_t *peer);
err_t wireguardifDeviceOutput(wireguard_device_t *device, sbuf_t *q, const ip_addr_t *ipaddr, uint16_t port);
void  wireguardifSendKeepalive(wireguard_device_t *device, wireguard_peer_t *peer);
err_t wireguardifOutputToPeer(wireguard_device_t *device, sbuf_t *q, const ip_addr_t *ipaddr, wireguard_peer_t *peer);

/***************************************** WireGuard Device ****************************************** */

void wireguardInit(void);
bool wireguardDeviceInit(wireguard_device_t *device, const uint8_t *private_key);
bool wireguardPeerInit(wireguard_device_t *device, wireguard_peer_t *peer, const uint8_t *public_key,
                       const uint8_t *preshared_key);

wireguard_peer_t *peerAlloc(wireguard_device_t *device);
uint8_t           wireguardPeerIndex(wireguard_device_t *device, wireguard_peer_t *peer);
wireguard_peer_t *peerLookupByPubkey(wireguard_device_t *device, uint8_t *public_key);
wireguard_peer_t *peerLookupByPeerIndex(wireguard_device_t *device, uint8_t peer_index);
wireguard_peer_t *peerLookupByReceiver(wireguard_device_t *device, uint32_t receiver);
wireguard_peer_t *peerLookupByHandshake(wireguard_device_t *device, uint32_t receiver);

void wireguardStartSession(wireguard_peer_t *peer, bool initiator);
void keypairUpdate(wireguard_peer_t *peer, wireguard_keypair_t *received_keypair);
void keypairDestroy(wireguard_keypair_t *keypair);

wireguard_keypair_t *getPeerKeypairForIdx(wireguard_peer_t *peer, uint32_t idx);
bool                 wireguardCheckReplay(wireguard_keypair_t *keypair, uint64_t seq);
uint8_t              wireguardGetMessageType(const uint8_t *data, size_t len);

wireguard_peer_t *wireguardProcessInitiationMessage(wireguard_device_t *device, message_handshake_initiation_t *msg);
bool              wireguardProcessHandshakeResponse(wireguard_device_t *device, wireguard_peer_t *peer,
                                                    message_handshake_response_t *src);
bool wireguardProcessCookieMessage(wireguard_device_t *device, wireguard_peer_t *peer, message_cookie_reply_t *src);

bool wireguardCreateHandshakeInitiation(wireguard_device_t *device, wireguard_peer_t *peer,
                                        message_handshake_initiation_t *dst);
bool wireguardCreateHandshakeResponse(wireguard_device_t *device, wireguard_peer_t *peer,
                                      message_handshake_response_t *dst);
void wireguardCreateCookieReply(wireguard_device_t *device, message_cookie_reply_t *dst, const uint8_t *mac1,
                                uint32_t index, uint8_t *source_addr_port, size_t source_length);

bool wireguardCheckMac1(wireguard_device_t *device, const uint8_t *data, size_t len, const uint8_t *mac1);
bool wireguardCheckMac2(wireguard_device_t *device, const uint8_t *data, size_t len, uint8_t *source_addr_port,
                        size_t source_length, const uint8_t *mac2);

bool wireguardExpired(uint32_t created_millis, uint32_t valid_seconds);

void wireguardEncryptPacket(uint8_t *dst, const uint8_t *src, size_t src_len, wireguard_keypair_t *keypair);
bool wireguardDecryptPacket(uint8_t *dst, const uint8_t *src, size_t src_len, uint64_t counter,
                            wireguard_keypair_t *keypair);

// test all encryption and decryption functions
void testWireGuardImpl(void);
