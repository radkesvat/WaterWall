#pragma once

#include "netinet.h"
#include "wireguard_endianhelpers.h"
#include "wireguard_types.h"
#include "wwapi.h"

// getTickMS
// getRandomBytes
// getTAI64N
// isSystemUnderLoad

typedef struct wgd_tstate_s
{
    // this is th real wireguard device that we built using data
    wireguard_device_t wg_device;
    wireguard_peer_t   peers[WIREGUARD_MAX_PEERS];
    uint16             peers_count;

    // the data that came from json configuration, we build real wireguard device from this
    wgdevice_init_data_t device_configuration;
    wgpeer_init_data_t  *peers_configuration;
    uint16               peers_configuration_count;

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

WW_EXPORT void wireguarddeviceTunnelOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset);
WW_EXPORT void wireguarddeviceTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain);
WW_EXPORT void wireguarddeviceTunnelOnPrepair(tunnel_t *t);
WW_EXPORT void wireguarddeviceTunnelOnStart(tunnel_t *t);

WW_EXPORT void wireguarddeviceTunnelUpStreamInit(tunnel_t *t, line_t *l);
WW_EXPORT void wireguarddeviceTunnelUpStreamEst(tunnel_t *t, line_t *l);
WW_EXPORT void wireguarddeviceTunnelUpStreamFinish(tunnel_t *t, line_t *l);
WW_EXPORT void wireguarddeviceTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
WW_EXPORT void wireguarddeviceTunnelUpStreamPause(tunnel_t *t, line_t *l);
WW_EXPORT void wireguarddeviceTunnelUpStreamResume(tunnel_t *t, line_t *l);

WW_EXPORT void wireguarddeviceTunnelDownStreamInit(tunnel_t *t, line_t *l);
WW_EXPORT void wireguarddeviceTunnelDownStreamEst(tunnel_t *t, line_t *l);
WW_EXPORT void wireguarddeviceTunnelDownStreamFinish(tunnel_t *t, line_t *l);
WW_EXPORT void wireguarddeviceTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf);
WW_EXPORT void wireguarddeviceTunnelDownStreamPause(tunnel_t *t, line_t *l);
WW_EXPORT void wireguarddeviceTunnelDownStreamResume(tunnel_t *t, line_t *l);

void wireguarddeviceLinestateInitialize(wgd_lstate_t *ls);
void wireguarddeviceLinestateDestroy(wgd_lstate_t *ls);

/* wireguard device cycle is the heart of the device that is by defalut runs every 400 ms*/
void wdevCycle(wgd_tstate_t *ts);

typedef int err_t; // it is in lwip but anyway...

// Initialise a new WireGuard network interface (ts)
err_t wireguardifInit(wgd_tstate_t *ts);

// Helper to initialise the peer struct with defaults
void wireguardifPeerInit(wgdevice_init_data_t *peer);

// Add a new peer to the specified interface - see wireguard.h for maximum number of peers allowed
// On success the peer_index can be used to reference this peer in future function calls
err_t wireguardifAddPeer(wgd_tstate_t *ts, wgdevice_init_data_t *peer, uint8_t *peer_index);

// Remove the given peer from the network interface
err_t wireguardifRemovePeer(wgd_tstate_t *ts, uint8_t peer_index);

// Update the "connect" IP of the given peer
err_t wireguardifUpdateEndpoint(wgd_tstate_t *ts, uint8_t peer_index, const ip_address_t *ip, uint16_t port);

// Try and connect to the given peer
err_t wireguardifConnect(wgd_tstate_t *ts, uint8_t peer_index);

// Stop trying to connect to the given peer
err_t wireguardifDisconnect(wgd_tstate_t *ts, uint8_t peer_index);

// Is the given peer "up"? A peer is up if it has a valid session key it can communicate with
err_t wireguardifPeerIsUp(wgd_tstate_t *ts, uint8_t peer_index, ip_address_t *current_ip, uint16_t *current_port);

err_t wireguardifPeerOutput(wgd_tstate_t *ts, sbuf_t *q, wireguard_peer_t *peer);
err_t wireguardifDeviceOutput(wireguard_device_t *device, sbuf_t *q, const ip_address_t *ipaddr, uint16_t port);

// Function declarations with camelBack naming:
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

bool wireguardBase64Decode(const char *str, uint8_t *out, size_t *outlen);
bool wireguardBase64Encode(const uint8_t *in, size_t inlen, char *out, size_t *outlen);
