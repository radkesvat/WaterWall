/*
 * Copyright (c) 2021 Daniel Hope (www.floorsense.nz)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 * 3. Neither the name of "Floorsense Ltd", "Agile Workspace Ltd" nor the names of
 *  its contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Daniel Hope <daniel.hope@smartalock.com>
 */


#ifndef _WIREGUARDIF_H_
#define _WIREGUARDIF_H_

#include "lwip/arch.h"
#include "lwip/netif.h"
#include "lwip/ip_addr.h"

// Default MTU for WireGuard is 1420 bytes
#define WIREGUARDIF_MTU (1420)

#define WIREGUARDIF_DEFAULT_PORT		(51820)
#define WIREGUARDIF_KEEPALIVE_DEFAULT	(0xFFFF)

typedef struct wireguardif_init_data {
	// Required: the private key of this WireGuard network interface
	const char *private_key;
	// Required: What UDP port to listen on
	u16_t listen_port;
	// Optional: restrict send/receive of encapsulated WireGuard traffic to this network interface only (NULL to use routing table)
	struct netif *bind_netif;
} wireguardif_init_data_t;

typedef struct wireguardif_peer {
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
	u16_t endport_port;
	u16_t keep_alive;
} wireguardif_peer_t;

#define WIREGUARDIF_INVALID_INDEX (0xFF)

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


#endif /* _WIREGUARDIF_H_ */
