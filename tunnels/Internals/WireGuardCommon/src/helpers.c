#include "peer_store.h"

#include "loggers/network_logger.h"

static bool wireguardCommonAllowedIpMatches(const wireguard_allowed_ip_t *allowed, const ip_addr_t *ipaddr)
{
    if ((! allowed->valid) || (ipaddr == NULL))
    {
        return false;
    }

    if ((ipaddr->type == IPADDR_TYPE_V4) && (allowed->ip.type == IPADDR_TYPE_V4))
    {
        return ip4AddrNetcmp(ip_2_ip4(ipaddr), ip_2_ip4(&allowed->ip), ip_2_ip4(&allowed->mask)) != 0;
    }

    if ((ipaddr->type == IPADDR_TYPE_V6) && (allowed->ip.type == IPADDR_TYPE_V6))
    {
        return ip6AddrNetcmp(ip_2_ip6(ipaddr), ip_2_ip6(&allowed->ip), ip_2_ip6(&allowed->mask)) != 0;
    }

    return false;
}

bool wireguardCommonPeerAllowsIp(const wireguard_peer_t *peer, const ip_addr_t *ipaddr)
{
    if ((peer == NULL) || (ipaddr == NULL))
    {
        return false;
    }

    for (int x = 0; x < WIREGUARD_MAX_SRC_IPS; ++x)
    {
        if (wireguardCommonAllowedIpMatches(&peer->allowed_source_ips[x], ipaddr))
        {
            return true;
        }
    }

    return false;
}

err_t wireguardifPeerOutput(wireguard_device_t *device, sbuf_t *packet, wireguard_peer_t *peer, bool data)
{
    assert(device->callbacks.output != NULL);
    const uint32_t received    = peer->authenticated_receives;
    const uint32_t sent        = peer->authenticated_sends;
    const bool     owed_reply  = peer->passive_keepalive;
    const uint32_t reply_since = peer->passive_keepalive_millis;
    const uint32_t now         = wireguardRecoveryNow();

    /* The carrier may synchronously deliver more data. A new passive reply must
     * start at that receive, independently of the reply this output satisfies. */
    peer->passive_keepalive = false;
    wireguardBeginProcessing(device);
    const bool accepted = device->callbacks.output(device->context, packet, peer, &peer->ip, peer->port);
    if (! accepted)
    {
        if (owed_reply && peer->valid && sent == peer->authenticated_sends)
        {
            peer->passive_keepalive        = true;
            peer->passive_keepalive_millis = reply_since;
        }
    }
    else if (peer->valid)
    {
        ++peer->authenticated_sends;
        if (data && received == peer->authenticated_receives && peer->unanswered_interval_ms == 0)
        {
            peer->unanswered_millis = now;
            peer->unanswered_interval_ms =
                (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT) * 1000U + fastRandRange32(0, REKEY_TIMEOUT_JITTER_MS);
        }
    }
    wireguardEndProcessing(device);
    return accepted ? ERR_OK : ERR_CONN;
}

err_t wireguardifDeviceOutput(wireguard_device_t *device, sbuf_t *packet, const ip_addr_t *ip, uint16_t port)
{
    assert(device->callbacks.output != NULL);
    return device->callbacks.output(device->context, packet, NULL, ip, port) ? ERR_OK : ERR_CONN;
}

static bool peerAddIp(wireguard_peer_t *peer, ip_addr_t ip, ip_addr_t mask)
{
    for (size_t i = 0; i < WIREGUARD_MAX_SRC_IPS; ++i)
    {
        wireguard_allowed_ip_t *allowed = &peer->allowed_source_ips[i];
        if (! allowed->valid)
        {
            if (! wireguardPeerIndexRange(peer, &ip, &mask))
                return false;
            *allowed = (wireguard_allowed_ip_t) {.valid = true, .ip = ip, .mask = mask};
            return true;
        }
        if (ipAddrCmp(&allowed->ip, &ip) && ipAddrCmp(&allowed->mask, &mask))
            return true;
    }
    return false;
}

static err_t wireguardifLookupPeer(wireguard_device_t *device, size_t peer_index, wireguard_peer_t **out);

err_t wireguardifAddPeer(wireguard_device_t *device, wireguard_peer_init_data_t *p, size_t *peer_index)
{
    assert(p != NULL);

    err_t             result;
    uint8_t           public_key[WIREGUARD_PUBLIC_KEY_LEN] = {0};
    size_t            public_key_len                       = sizeof(public_key);
    wireguard_peer_t *peer                                 = NULL;

    if (stringLength((const char *) p->public_key) != BASE64_ENCODE_OUT_SIZE(public_key_len))
    {
        return ERR_ARG;
    }

    if (wwBase64DecodeCanonical((const char *) p->public_key,
                                (unsigned int) stringLength((const char *) p->public_key),
                                public_key,
                                sizeof(public_key)) != WIREGUARD_PUBLIC_KEY_LEN)
    {
        wCryptoZero(public_key, sizeof(public_key));
        return ERR_ARG;
    }

    // See if the peer is already registered
    peer = peerLookupByPubkey(device, public_key);
    if (! peer)
    {
        peer = wireguardPeerCreate(device, public_key, p->preshared_key);
        if (peer == NULL)
        {
            result = ERR_ARG;
        }
        else if (! peerAddIp(peer, p->allowed_ip, p->allowed_mask))
        {
            discard wireguardifRemovePeer(device, peer->id);
            peer   = NULL;
            result = ERR_MEM;
        }
        else
        {
            peer->connect_ip   = p->endpoint_ip;
            peer->connect_port = p->endpoint_port;
            peer->ip           = peer->connect_ip;
            peer->port         = peer->connect_port;
            peer->keepalive_interval =
                p->keep_alive == WIREGUARDIF_KEEPALIVE_DEFAULT ? KEEPALIVE_TIMEOUT : p->keep_alive;
            memoryCopy(peer->greatest_timestamp, p->greatest_timestamp, sizeof(peer->greatest_timestamp));
            result = ERR_OK;
        }
    }
    else
    {
        result = ERR_OK;
    }

    if (peer_index != NULL)
        *peer_index = peer != NULL ? peer->id : WIREGUARDIF_INVALID_INDEX;
    wCryptoZero(public_key, sizeof(public_key));
    return result;
}

err_t wireguardifAddAllowedIp(wireguard_device_t *device, size_t peer_index, const ip_addr_t *ip, const ip_addr_t *mask)
{
    wireguard_peer_t *peer;
    err_t             result = wireguardifLookupPeer(device, peer_index, &peer);

    if (result != ERR_OK)
    {
        return result;
    }

    if ((ip == NULL) || (mask == NULL))
    {
        return ERR_ARG;
    }

    return peerAddIp(peer, *ip, *mask) ? ERR_OK : ERR_MEM;
}

void wireguardifSendKeepalive(wireguard_device_t *device, wireguard_peer_t *peer)
{
    // Send a NULL packet as a keep-alive
    sbuf_t *empty_buf = bufferpoolGetSmallBuffer(getCurrentWorkerBufferPool());
    wireguardifOutputToPeer(device, empty_buf, NULL, peer);
}

static err_t wireguardifLookupPeer(wireguard_device_t *device, size_t peer_index, wireguard_peer_t **out)
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

err_t wireguardifDisconnect(wireguard_device_t *device, size_t peer_index)
{
    wireguard_peer_t *peer;
    err_t             result = wireguardifLookupPeer(device, peer_index, &peer);
    if (result == ERR_OK)
    {
        // Set the flag that we want to try connecting
        peer->active = false;
        peer->send_handshake         = false;
        peer->retry_handshake        = false;
        peer->passive_keepalive      = false;
        peer->unanswered_interval_ms = 0;
        // Wipe out current keys
        keypairDestroy(&peer->next_keypair);
        keypairDestroy(&peer->curr_keypair);
        keypairDestroy(&peer->prev_keypair);
        wireguardClearHandshakeState(peer);
        peer->session_erase_millis = 0;
        peer->session_erase_armed  = false;
        result                     = ERR_OK;
    }
    return result;
}

void wireguardifPeerInit(wireguard_peer_init_data_t *peer)
{
    assert(peer != NULL);
    memoryZero(peer, sizeof(wireguard_peer_init_data_t));
    // Caller must provide 'public_key'
    peer->public_key = NULL;
    ipAddrSetAny(false, &peer->endpoint_ip);
    peer->endpoint_port = WIREGUARDIF_DEFAULT_PORT;
    peer->keep_alive    = WIREGUARDIF_KEEPALIVE_DEFAULT;
    ipAddrSetAny(false, &peer->allowed_ip);
    ipAddrSetAny(false, &peer->allowed_mask);
    memoryZero(peer->greatest_timestamp, sizeof(peer->greatest_timestamp));
    peer->preshared_key = NULL;
}
