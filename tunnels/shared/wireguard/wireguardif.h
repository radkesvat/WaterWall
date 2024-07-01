#pragma once
/*
    Most of the code is taken and renamed, from the awesome projects wireguard-lwip and lwip

    Author of lwip:              Adam Dunkels  https://github.com/smartalock/wireguard-lwip
    Author of wireguard-lwip:    Daniel Hope   https://github.com/lwip-tcpip/lwip

    their license files are placed next to this file
*/

#include "lwip_types.h"

// Default MTU for WireGuard is 1420 bytes

enum
{
    kWgIFMtu            = 1420,
    kWgDefaultPort      = 51820,
    kWgDefaultKeepAlive = 0xFFFF,
    kWgIFInvalidIndex   = 0xFF
};

typedef struct wireguardif_init_data_s
{
    // Required: the private key of this WireGuard network interface
    const char *private_key;
    // Required: What UDP port to listen on
    uint16_t listen_port;
    // Optional: restrict send/receive of encapsulated WireGuard traffic to this network interface only (NULL to use
    // routing table)
    struct netif *bind_netif;

} wireguardif_init_data_t;

typedef struct wireguardif_peer_s
{
    const char *public_key;
    // Optional pre-shared key (32 bytes) - make sure this is NULL if not to be used
    const uint8_t *preshared_key;
    // tai64n of largest timestamp we have seen during handshake to avoid replays
    uint8_t greatest_timestamp[12];

    // Allowed ip/netmask (can add additional later but at least one is required)
    ip_addr_t allowed_ip;
    ip_addr_t allowed_mask;

    // End-point details (may be blank)
    ip_addr_t endpoint_ip;
    uint16_t  endport_port;
    uint16_t  keep_alive;

} wireguardif_peer_t;

/* static struct netif wg_netif_struct = {0};
 * struct wireguard_interface wg;
 * wg.private_key = "abcdefxxx..xxxxx=";
 * wg.listen_port = 51820;
 * wg.bind_netif = NULL; // Pass netif to listen on, NULL for all interfaces
 *
 * netif = netif_add(&netif_struct, &ipaddr, &netmask, &gateway, &wg, &wireguardif_init, &ip_input);
 *
 * netif_set_up(wg_net);
 *
 * struct wireguardif_peer peer;
 * wireguardif_peer_init(&peer);
 * peer.public_key = "apoehc...4322abcdfejg=;
 * peer.preshared_key = NULL;
 * peer.allowed_ip = allowed_ip;
 * peer.allowed_mask = allowed_mask;
 *
 * // If you want to enable output connection
 * peer.endpoint_ip = peer_ip;
 * peer.endport_port = 12345;
 *
 * uint8_t wireguard_peer_index;
 * wireguardif_add_peer(netif, &peer, &wireguard_peer_index);
 *
 * if ((wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) && !ip_addr_isany(&peer.endpoint_ip)) {
 *   // Start outbound connection to peer
 *   wireguardif_connect(wg_net, wireguard_peer_index);
 * }
 *
 */

// Initialise a new WireGuard network interface (netif)
err_t wireguardIFInit(struct netif *netif);

// Helper to initialise the peer struct with defaults
void wireguardIFPeerInit(struct wireguardif_peer_s *peer);

// Add a new peer to the specified interface - see wireguard.h for maximum number of peers allowed
// On success the peer_index can be used to reference this peer in future function calls
err_t wireguardIFAddPeer(struct netif *netif, struct wireguardif_peer_s *peer, uint8_t *peer_index);

// Remove the given peer from the network interface
err_t wireguardIFRemovePeer(struct netif *netif, uint8_t peer_index);

// Update the "connect" IP of the given peer
err_t wireguardIFUpdateEndpoint(struct netif *netif, uint8_t peer_index, const ip_addr_t *ip, uint16_t port);

// Try and connect to the given peer
err_t wireguardIFConnect(struct netif *netif, uint8_t peer_index);

// Stop trying to connect to the given peer
err_t wireguardIFDisconnect(struct netif *netif, uint8_t peer_index);

// Is the given peer "up"? A peer is up if it has a valid session key it can communicate with
err_t wireguardIFPeerIsUp(struct netif *netif, uint8_t peer_index, ip_addr_t *current_ip, uint16_t *current_port);
