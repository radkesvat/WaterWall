#include "peer_store.h"

#include "WireGuardCommon/prefix.h"
#include "loggers/network_logger.h"

typedef struct wireguard_public_key_s
{
    uint8_t bytes[WIREGUARD_PUBLIC_KEY_LEN];
} wireguard_public_key_t;

static size_t publicKeyHash(const wireguard_public_key_t *key)
{
    return (size_t) calcHashBytes(key->bytes, sizeof(key->bytes));
}

static bool publicKeyEquals(const wireguard_public_key_t *a, const wireguard_public_key_t *b)
{
    return memcmp(a->bytes, b->bytes, sizeof(a->bytes)) == 0;
}

#define i_type wg_public_key_map_t
#define i_key  wireguard_public_key_t
#define i_val  wireguard_peer_t *
#define i_hash publicKeyHash
#define i_eq   publicKeyEquals
#include "stc/hmap.h"

#define i_type wg_index_map_t
#define i_key  size_t
#define i_val  wireguard_peer_t *
#include "stc/hmap.h"

typedef struct wireguard_peer_store_s
{
    wg_public_key_map_t      keys;
    wg_index_map_t           ids, receivers;
    wireguard_prefix_table_t routes;
} wireguard_peer_store_t;

wireguard_peer_t *peerLookupByPubkey(wireguard_device_t *device, const uint8_t *key)
{
    if (device->store == NULL)
        return NULL;
    wireguard_public_key_t public_key;
    memoryCopy(public_key.bytes, key, sizeof(public_key.bytes));
    const wg_public_key_map_t_value *entry = wg_public_key_map_t_get(&device->store->keys, public_key);
    return entry != NULL ? entry->second : NULL;
}

wireguard_peer_t *peerLookupByPeerIndex(wireguard_device_t *device, size_t id)
{
    if (device->store == NULL)
        return NULL;
    const wg_index_map_t_value *entry = wg_index_map_t_get(&device->store->ids, id);
    return entry != NULL ? entry->second : NULL;
}

wireguard_peer_t *wireguardPeerCreate(wireguard_device_t *device, const uint8_t *key, const uint8_t *psk)
{
    if (! device->valid || peerLookupByPubkey(device, key) != NULL)
        return NULL;
    wireguard_peer_t *peer = memoryAllocate(sizeof(*peer));
    if (! wireguardPeerInit(device, peer, key, psk))
    {
        memoryFree(peer);
        return NULL;
    }
    if (device->store == NULL)
        device->store = memoryAllocateZero(sizeof(*device->store));
    wireguard_public_key_t public_key;
    memoryCopy(public_key.bytes, key, sizeof(public_key.bytes));
    /* On wrap, skip the API sentinel and every id still in use. The peer
     * allocations themselves leave ample unused ids even on 32-bit hosts. */
    size_t id = device->next_peer_id;
    while (id == WIREGUARDIF_INVALID_INDEX || peerLookupByPeerIndex(device, id) != NULL)
        ++id;
    if (! wg_public_key_map_t_insert(&device->store->keys, public_key, peer).inserted)
        goto fail;
    if (! wg_index_map_t_insert(&device->store->ids, id, peer).inserted)
    {
        wg_public_key_map_t_erase(&device->store->keys, public_key);
        goto fail;
    }
    peer->id     = id;
    peer->device = device;
    peer->next   = device->first_peer;
    if (peer->next != NULL)
        peer->next->previous = peer;
    device->first_peer   = peer;
    device->next_peer_id = id + 1;
    ++device->peer_count;
    return peer;
fail:
    wCryptoZero(peer, sizeof(*peer));
    memoryFree(peer);
    return NULL;
}

static wireguard_peer_t *receiverOwner(wireguard_device_t *device, uint32_t receiver)
{
    if (device->store == NULL)
        return NULL;
    const wg_index_map_t_value *entry = wg_index_map_t_get(&device->store->receivers, receiver);
    return entry != NULL ? entry->second : NULL;
}

bool wireguardReceiverInUse(wireguard_device_t *device, uint32_t receiver)
{
    return receiverOwner(device, receiver) != NULL;
}

wireguard_peer_t *peerLookupByReceiver(wireguard_device_t *device, uint32_t receiver)
{
    wireguard_peer_t *peer = receiverOwner(device, receiver);
    return peer != NULL && getPeerKeypairForIdx(peer, receiver) != NULL ? peer : NULL;
}

wireguard_peer_t *peerLookupByHandshake(wireguard_device_t *device, uint32_t receiver)
{
    wireguard_peer_t *peer = receiverOwner(device, receiver);
    return peer != NULL && peer->handshake.valid && peer->handshake.initiator && peer->handshake.local_index == receiver
               ? peer
               : NULL;
}

wireguard_peer_t *peerLookupByPendingHandshake(wireguard_device_t *device, uint32_t receiver)
{
    wireguard_peer_t *peer = receiverOwner(device, receiver);
    return peer != NULL && peer->pending_handshake.valid && peer->pending_handshake.sender == receiver ? peer : NULL;
}

/* The same sender index can name a pending response, a handshake and a
 * transport key at different moments. Index their union, then check the role
 * in the lookup. Only protocol state transitions change this five-entry set. */
void wireguardPeerSyncReceivers(wireguard_peer_t *peer)
{
    if (peer->device == NULL)
        return; /* A standalone crypto operation does not publish receiver ids. */
    const uint32_t current[] = {peer->handshake.valid ? peer->handshake.local_index : 0,
                                peer->pending_handshake.valid ? peer->pending_handshake.sender : 0,
                                peer->curr_keypair.valid ? peer->curr_keypair.local_index : 0,
                                peer->prev_keypair.valid ? peer->prev_keypair.local_index : 0,
                                peer->next_keypair.valid ? peer->next_keypair.local_index : 0};
    static_assert(sizeof(current) == sizeof(peer->indexed_receivers), "receiver index fields");
    if (memcmp(current, peer->indexed_receivers, sizeof(current)) == 0)
        return;
    wg_index_map_t *map = &peer->device->store->receivers;
    for (size_t i = 0; i < sizeof(current) / sizeof(*current); ++i)
        if (peer->indexed_receivers[i] != 0)
            wg_index_map_t_erase(map, peer->indexed_receivers[i]);
    for (size_t i = 0; i < sizeof(current) / sizeof(*current); ++i)
    {
        if (current[i] == 0)
            continue;
        const wg_index_map_t_result existing = wg_index_map_t_insert(map, current[i], peer);
        if (UNLIKELY(existing.ref == NULL || existing.ref->second != peer))
        {
            LOGF("WireGuard: receiver index publication failed");
            abortProgramNow(1);
        }
    }
    memoryCopy(peer->indexed_receivers, current, sizeof(current));
}

bool wireguardPeerIndexRange(wireguard_peer_t *peer, const ip_addr_t *ip, const ip_addr_t *mask)
{
    return wireguardPrefixInsert(&peer->device->store->routes, ip, mask, peer->id, peer, false);
}

wireguard_peer_t *wireguardCommonPeerForIp(wireguard_device_t *device, const ip_addr_t *ip)
{
    return device->store != NULL && ip != NULL ? wireguardPrefixLookup(&device->store->routes, ip) : NULL;
}

err_t wireguardifRemovePeer(wireguard_device_t *device, size_t id)
{
    wireguard_peer_t *peer = peerLookupByPeerIndex(device, id);
    if (peer == NULL)
        return ERR_ARG;

    wireguard_public_key_t key;
    memoryCopy(key.bytes, peer->public_key, sizeof(key.bytes));
    wg_public_key_map_t_erase(&device->store->keys, key);
    wg_index_map_t_erase(&device->store->ids, id);
    for (size_t i = 0; i < sizeof(peer->indexed_receivers) / sizeof(*peer->indexed_receivers); ++i)
        if (peer->indexed_receivers[i] != 0)
            wg_index_map_t_erase(&device->store->receivers, peer->indexed_receivers[i]);
    for (size_t i = 0; i < WIREGUARD_MAX_SRC_IPS; ++i)
        if (peer->allowed_source_ips[i].valid)
            wireguardPrefixRemove(
                &device->store->routes, &peer->allowed_source_ips[i].ip, &peer->allowed_source_ips[i].mask, id);

    wireguard_peer_t *next = peer->next;
    if (peer->previous != NULL)
        peer->previous->next = next;
    else
        device->first_peer = next;
    if (next != NULL)
        next->previous = peer->previous;
    --device->peer_count;
    wCryptoZero(peer, sizeof(*peer));
    if (device->processing_depth != 0)
    {
        /* Any outer timer cursor may still reference this node and its successor. */
        peer->next            = next;
        peer->previous        = device->retired_peers;
        device->retired_peers = peer;
    }
    else
        memoryFree(peer);
    return ERR_OK;
}

void wireguardEndProcessing(wireguard_device_t *device)
{
    assert(device->processing_depth > 0);
    if (--device->processing_depth == 0)
    {
        while (device->retired_peers != NULL)
        {
            wireguard_peer_t *peer = device->retired_peers;
            device->retired_peers  = peer->previous;
            memoryFree(peer);
        }
    }
}

void wireguardPeerStoreDestroy(wireguard_device_t *device)
{
    assert(device->processing_depth == 0);
    if (device->store == NULL)
        return;
    while (device->first_peer != NULL)
        discard wireguardifRemovePeer(device, device->first_peer->id);
    wg_public_key_map_t_drop(&device->store->keys);
    wg_index_map_t_drop(&device->store->ids);
    wg_index_map_t_drop(&device->store->receivers);
    wireguardPrefixDestroy(&device->store->routes);
    memoryFree(device->store);
}
