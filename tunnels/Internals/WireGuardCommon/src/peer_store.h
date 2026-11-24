#pragma once
#include "WireGuardCommon/engine.h"

bool wireguardPeerInit(wireguard_device_t *device, wireguard_peer_t *peer, const uint8_t *public_key,
                       const uint8_t *preshared_key);
void wireguardPeerSyncReceivers(wireguard_peer_t *peer);
bool wireguardReceiverInUse(wireguard_device_t *device, uint32_t receiver);
bool wireguardPeerIndexRange(wireguard_peer_t *peer, const ip_addr_t *ip, const ip_addr_t *mask);
void wireguardPeerStoreDestroy(wireguard_device_t *device);

static inline void wireguardBeginProcessing(wireguard_device_t *device)
{
    ++device->processing_depth;
}
void wireguardEndProcessing(wireguard_device_t *device);
