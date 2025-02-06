#pragma once

#include "wwapi.h"

// Default MTU for WireGuard is 1420 bytes
#define WIREGUARDIF_MTU (1420)

#define WIREGUARDIF_DEFAULT_PORT      (51820)
#define WIREGUARDIF_KEEPALIVE_DEFAULT (0xFFFF)

/*
    * WireGuard device initialisation data
    we parse json to get this data

*/

typedef struct wgdevice_init_data_s
{
    // Required: the private key of this WireGuard network interface
    const char *private_key;
    // Required: What UDP port to listen on
    uint16 listen_port;
    // Optional: restrict send/receive of encapsulated WireGuard traffic to this network interface only (NULL to use
    // routing table)
    struct netif *bind_netif;
} wgdevice_init_data_t;

typedef struct wgpeer_init_data_s
{
    const char *public_key;
    // Optional pre-shared key (32 bytes) - make sure this is NULL if not to be used
    const uint8_t *preshared_key;
    // tai64n of largest timestamp we have seen during handshake to avoid replays
    uint8_t greatest_timestamp[12];

    // Allowed ip/netmask (can add additional later but at least one is required)
    sockaddr_u allowed_ip;
    sockaddr_u allowed_mask;

    // End-point details (may be blank)
    ip_address_t endpoint_ip;
    uint16       endport_port;
    uint16       keep_alive;
} wgpeer_init_data_t;

typedef struct wireguarddevice_tstate_s
{
    wgdevice_init_data_t device_configuration;
    wgpeer_init_data_t  *peers_configuration;
    uint16               peers_count;

} wireguarddevice_tstate_t;

typedef struct wireguarddevice_lstate_s
{
    int xxx;
} wireguarddevice_lstate_t;

enum
{
    kTunnelStateSize = sizeof(wireguarddevice_tstate_t),
    kLineStateSize   = sizeof(wireguarddevice_lstate_t)
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

void wireguarddeviceLinestateInitialize(wireguarddevice_lstate_t *ls);
void wireguarddeviceLinestateDestroy(wireguarddevice_lstate_t *ls);
