#include "structure.h"
#include "wcrypto.h"

#include "loggers/network_logger.h"

err_t wireguardifPeerOutput(wireguard_device_t *device, sbuf_t *q, wireguard_peer_t *peer)
{
    bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), q);
    // Send to last know port, not the connect port
    // TODO: Support DSCP and ECN - lwip requires this set on PCB globally, not per packet
    return udpSendTo(device->udp_pcb, q, &peer->ip, peer->port);
}

err_t wireguardifDeviceOutput(wireguard_device_t *device, sbuf_t *q, const ip_addr_t *ipaddr, uint16_t port)
{
    bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), q);

    return udpSendTo(device->udp_pcb, q, ipaddr, port);
}

static bool peerAddIp(wireguard_peer_t *peer, ip_addr_t ip, ip_addr_t mask)
{
    bool                    result = false;
    wireguard_allowed_ip_t *allowed;
    int                     x;
    // Look for existing match first
    for (x = 0; x < WIREGUARD_MAX_SRC_IPS; x++)
    {
        allowed = &peer->allowed_source_ips[x];
        if ((allowed->valid) && ipAddrCmp(&allowed->ip, &ip) && ipAddrCmp(&allowed->mask, &mask))
        {
            result = true;
            break;
        }
    }
    if (! result)
    {
        // Look for a free slot
        for (x = 0; x < WIREGUARD_MAX_SRC_IPS; x++)
        {
            allowed = &peer->allowed_source_ips[x];
            if (! allowed->valid)
            {
                allowed->valid = true;
                allowed->ip    = ip;
                allowed->mask  = mask;
                result         = true;
                break;
            }
        }
    }
    return result;
}

err_t wireguardifAddPeer(wireguard_device_t *device, wireguard_peer_init_data_t *p, uint8_t *peer_index)
{
    assert(p != NULL);

    err_t             result;
    uint8_t           public_key[WIREGUARD_PUBLIC_KEY_LEN];
    size_t            public_key_len = sizeof(public_key);
    wireguard_peer_t *peer           = NULL;

    uint32_t t1 = getTickMS();

    if (stringLength((const char *) p->public_key) / 4 != public_key_len)
    {
        return ERR_ARG;
    }

    wwBase64Decode((const char *) p->public_key, stringLength((const char *) p->public_key), public_key);

    // See if the peer is already registered
    peer = peerLookupByPubkey(device, public_key);
    if (! peer)
    {
        // Not active - see if we have room to allocate a new one
        peer = peerAlloc(device);
        if (peer)
        {

            if (wireguardPeerInit(device, peer, public_key, p->preshared_key))
            {

                peer->connect_ip   = p->endpoint_ip;
                peer->connect_port = p->endpoint_port;
                peer->ip           = peer->connect_ip;
                peer->port         = peer->connect_port;
                if (p->keep_alive == WIREGUARDIF_KEEPALIVE_DEFAULT)
                {
                    peer->keepalive_interval = KEEPALIVE_TIMEOUT;
                }
                else
                {
                    peer->keepalive_interval = p->keep_alive;
                }
                peerAddIp(peer, p->allowed_ip, p->allowed_mask);
                memcpy(peer->greatest_timestamp, p->greatest_timestamp, sizeof(peer->greatest_timestamp));

                result = ERR_OK;
            }
            else
            {
                result = ERR_ARG;
            }
        }
        else
        {
            result = ERR_MEM;
        }
    }
    else
    {
        result = ERR_OK;
    }

    uint32_t t2 = getTickMS();
    LOGD("Adding peer took %ums\r\n", (t2 - t1));

    if (peer_index)
    {
        if (peer)
        {
            *peer_index = wireguardPeerIndex(device, peer);
        }
        else
        {
            *peer_index = WIREGUARDIF_INVALID_INDEX;
        }
    }
    return result;
}

void wireguardifSendKeepalive(wireguard_device_t *device, wireguard_peer_t *peer)
{
    // Send a NULL packet as a keep-alive
    wireguardifOutputToPeer(device, NULL, NULL, peer);
}

static err_t wireguardifLookupPeer(wireguard_device_t *device, uint8_t peer_index, wireguard_peer_t **out)
{
    assert(device != NULL);
    wireguard_peer_t *peer = NULL;
    err_t             result;

    if (device->valid)
    {
        peer = peerLookupByPeerIndex(device, peer_index);
        if (peer)
        {
            result = ERR_OK;
        }
        else
        {
            result = ERR_ARG;
        }
    }
    else
    {
        result = ERR_ARG;
    }
    *out = peer;
    return result;
}

err_t wireguardifPeerIsUp(wireguard_device_t *device, uint8_t peer_index, ip_addr_t *current_ip, uint16_t *current_port)
{
    wireguard_peer_t *peer;
    err_t             result = wireguardifLookupPeer(device, peer_index, &peer);
    if (result == ERR_OK)
    {
        if ((peer->curr_keypair.valid) || (peer->prev_keypair.valid))
        {
            result = ERR_OK;
        }
        else
        {
            result = ERR_CONN;
        }
        if (current_ip)
        {
            *current_ip = peer->ip;
        }
        if (current_port)
        {
            *current_port = peer->port;
        }
    }
    return result;
}

err_t wireguardifRemovePeer(wireguard_device_t *device, uint8_t peer_index)
{
    wireguard_peer_t *peer;
    err_t             result = wireguardifLookupPeer(device, peer_index, &peer);
    if (result == ERR_OK)
    {
        wCryptoZero(peer, sizeof(wireguard_peer_t));
        peer->valid = false;
        result      = ERR_OK;
    }
    return result;
}

err_t wireguardifUpdateEndpoint(wireguard_device_t *device, uint8_t peer_index, const ip_addr_t *ip, uint16_t port)
{
    wireguard_peer_t *peer;
    err_t             result = wireguardifLookupPeer(device, peer_index, &peer);
    if (result == ERR_OK)
    {
        peer->connect_ip   = *ip;
        peer->connect_port = port;
        result             = ERR_OK;
    }
    return result;
}

err_t wireguardifConnect(wireguard_device_t *device, uint8_t peer_index)
{
    wireguard_peer_t *peer;
    err_t             result = wireguardifLookupPeer(device, peer_index, &peer);
    if (result == ERR_OK)
    {
        // Check that a valid connect ip and port have been set
        if (! ipAddrIsAny(&peer->connect_ip) && (peer->connect_port > 0))
        {
            // Set the flag that we want to try connecting
            peer->active = true;
            peer->ip     = peer->connect_ip;
            peer->port   = peer->connect_port;
            result       = ERR_OK;
        }
        else
        {
            result = ERR_ARG;
        }
    }
    return result;
}

err_t wireguardifDisconnect(wireguard_device_t *device, uint8_t peer_index)
{
    wireguard_peer_t *peer;
    err_t             result = wireguardifLookupPeer(device, peer_index, &peer);
    if (result == ERR_OK)
    {
        // Set the flag that we want to try connecting
        peer->active = false;
        // Wipe out current keys
        keypairDestroy(&peer->next_keypair);
        keypairDestroy(&peer->curr_keypair);
        keypairDestroy(&peer->prev_keypair);
        result = ERR_OK;
    }
    return result;
}

void wireguardifPeerInit(wireguard_peer_init_data_t *peer)
{
    assert(peer != NULL);
    memset(peer, 0, sizeof(wireguard_peer_init_data_t));
    // Caller must provide 'public_key'
    peer->public_key = NULL;
    ipAddrSetAny(false, &peer->endpoint_ip);
    peer->endpoint_port = WIREGUARDIF_DEFAULT_PORT;
    peer->keep_alive    = WIREGUARDIF_KEEPALIVE_DEFAULT;
    ipAddrSetAny(false, &peer->allowed_ip);
    ipAddrSetAny(false, &peer->allowed_mask);
    memset(peer->greatest_timestamp, 0, sizeof(peer->greatest_timestamp));
    peer->preshared_key = NULL;
}
