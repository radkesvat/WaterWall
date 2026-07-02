#include "structure.h"

#include "loggers/network_logger.h"

static uint8_t wireguarddeviceCountMaskBits32(uint32_t value)
{
    uint8_t bits = 0;

    while (value != 0)
    {
        value &= (value - 1U);
        bits++;
    }

    return bits;
}

static bool wireguarddeviceAllowedIpMatches(const wireguard_allowed_ip_t *allowed, const ip_addr_t *ipaddr)
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

static uint8_t wireguarddeviceAllowedIpPrefixBits(const wireguard_allowed_ip_t *allowed)
{
    if (! allowed->valid)
    {
        return 0;
    }

    if (allowed->mask.type == IPADDR_TYPE_V4)
    {
        return wireguarddeviceCountMaskBits32(ip_2_ip4(&allowed->mask)->addr);
    }

    if (allowed->mask.type == IPADDR_TYPE_V6)
    {
        uint8_t bits = 0;

        for (int i = 0; i < 4; ++i)
        {
            bits += wireguarddeviceCountMaskBits32(ip_2_ip6(&allowed->mask)->addr[i]);
        }

        return bits;
    }

    return 0;
}

void wireguarddeviceStateLock(wgd_tstate_t *state)
{
    assert(state != NULL);

    mutexLock(&state->mutex);
}

void wireguarddeviceStateUnlock(wgd_tstate_t *state)
{
    assert(state != NULL);

    mutexUnlock(&state->mutex);
}

bool wireguarddeviceTransportSideIsNext(const wgd_tstate_t *state)
{
    assert(state != NULL);

    return state->transport_side_is_next;
}

static void wireguarddeviceTransportLineInit(tunnel_t *t, line_t *line)
{
    wgd_tstate_t *state = tunnelGetState(t);

    if (wireguarddeviceTransportSideIsNext(state))
    {
        tunnelNextUpStreamInit(t, line);
        return;
    }

    tunnelPrevDownStreamInit(t, line);
}

line_t *wireguarddeviceEnsureTransportLine(wgd_tstate_t *state, wid_t wid)
{
    assert(state != NULL);
    assert(wid == getWID());

    tunnel_t       *tunnel = state->tunnel;
    tunnel_chain_t *chain  = tunnelGetChain(tunnel);

    if (state->transport_lines == NULL || chain == NULL || wid >= chain->workers_count)
    {
        return NULL;
    }

    line_t *line = state->transport_lines[wid];
    if (line != NULL && lineIsAlive(line))
    {
        return line;
    }

    line = lineCreate(tunnelchainGetLinePools(chain), wid);
    state->transport_lines[wid] = line;

    lineLock(line);
    wireguarddeviceTransportLineInit(tunnel, line);
    if (! lineIsAlive(line))
    {
        state->transport_lines[wid] = NULL;
        lineUnlock(line);
        return NULL;
    }
    lineUnlock(line);

    return line;
}

void wireguarddeviceCloseTransportLine(tunnel_t *t, wid_t wid)
{
    assert(wid == getWID());

    wgd_tstate_t *state = tunnelGetState(t);

    if (state->transport_lines == NULL)
    {
        return;
    }

    line_t *line = state->transport_lines[wid];
    state->transport_lines[wid] = NULL;

    if (line == NULL || ! lineIsAlive(line))
    {
        return;
    }

    lineLock(line);
    if (wireguarddeviceTransportSideIsNext(state))
    {
        tunnelNextUpStreamFinish(t, line);
    }
    else
    {
        tunnelPrevDownStreamFinish(t, line);
    }

    if (lineIsAlive(line))
    {
        lineDestroy(line);
    }
    lineUnlock(line);
}

void wireguarddeviceHandleTransportLineFinish(tunnel_t *t, line_t *line)
{
    wgd_tstate_t   *state = tunnelGetState(t);
    tunnel_chain_t *chain = tunnelGetChain(t);
    wid_t           wid;

    if (line == NULL || chain == NULL || state->transport_lines == NULL)
    {
        return;
    }

    wid = lineGetWID(line);
    if (wid >= chain->workers_count || state->transport_lines[wid] != line)
    {
        return;
    }

    state->transport_lines[wid] = NULL;
    if (lineIsAlive(line))
    {
        lineDestroy(line);
    }
}

bool wireguarddeviceForwardTransportPacket(wgd_tstate_t *state, line_t *line, sbuf_t *buf)
{
    tunnel_t *tunnel = state->tunnel;
    wid_t     wid    = lineGetWID(line);

    lineLock(line);
    if (wireguarddeviceTransportSideIsNext(state))
    {
        tunnelNextUpStreamPayload(tunnel, line, buf);
    }
    else
    {
        tunnelPrevDownStreamPayload(tunnel, line, buf);
    }

    if (! lineIsAlive(line))
    {
        if (state->transport_lines != NULL)
        {
            state->transport_lines[wid] = NULL;
        }
        lineUnlock(line);
        return false;
    }

    lineUnlock(line);
    return true;
}

void wireguarddeviceForwardInnerPacket(wgd_tstate_t *state, line_t *line, sbuf_t *buf)
{
    tunnel_t *tunnel = state->tunnel;

    if (wireguarddeviceTransportSideIsNext(state))
    {
        tunnelPrevDownStreamPayload(tunnel, line, buf);
        return;
    }

    tunnelNextUpStreamPayload(tunnel, line, buf);
}

wireguard_peer_t *wireguarddevicePeerLookupByAllowedIp(wireguard_device_t *device, const ip_addr_t *ipaddr)
{
    wireguard_peer_t *result      = NULL;
    uint8_t           best_prefix = 0;

    for (int x = 0; x < WIREGUARD_MAX_PEERS; ++x)
    {
        wireguard_peer_t *peer = &device->peers[x];

        if (! peer->valid)
        {
            continue;
        }

        for (int y = 0; y < WIREGUARD_MAX_SRC_IPS; ++y)
        {
            wireguard_allowed_ip_t *allowed = &peer->allowed_source_ips[y];

            if (! wireguarddeviceAllowedIpMatches(allowed, ipaddr))
            {
                continue;
            }

            uint8_t prefix_bits = wireguarddeviceAllowedIpPrefixBits(allowed);

            if ((result == NULL) || (prefix_bits > best_prefix))
            {
                result      = peer;
                best_prefix = prefix_bits;
            }
        }
    }

    return result;
}

bool wireguarddeviceCheckPeerAllowedIp(const wireguard_peer_t *peer, const ip_addr_t *ipaddr)
{
    if ((peer == NULL) || (ipaddr == NULL))
    {
        return false;
    }

    for (int x = 0; x < WIREGUARD_MAX_SRC_IPS; ++x)
    {
        if (wireguarddeviceAllowedIpMatches(&peer->allowed_source_ips[x], ipaddr))
        {
            return true;
        }
    }

    return false;
}

err_t wireguardifPeerOutput(wireguard_device_t *device, sbuf_t *q, wireguard_peer_t *peer)
{
    // Send to last know port, not the connect port
    // TODO: Support DSCP and ECN - lwip requires this set on PCB globally, not per packet
    wgd_tstate_t *ts            = (wgd_tstate_t *) device;
    ip_addr_t     endpoint_ip   = peer->ip;
    uint16_t      endpoint_port = peer->port;
    line_t       *line;
    bool          sent;

    wireguarddeviceStateUnlock(ts);
    line = wireguarddeviceEnsureTransportLine(ts, getWID());
    if (line == NULL)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), q);
        wireguarddeviceStateLock(ts);
        return ERR_CONN;
    }

    addresscontextSetIpPortProtocol(lineGetDestinationAddressContext(line), &endpoint_ip, endpoint_port, IP_PROTO_UDP);
    sent = wireguarddeviceForwardTransportPacket(ts, line, q);
    wireguarddeviceStateLock(ts);
    return sent ? ERR_OK : ERR_CONN;
    // return udpSendTo(device->udp_pcb, q, &peer->ip, peer->port);
}

err_t wireguardifDeviceOutput(wireguard_device_t *device, sbuf_t *q, const ip_addr_t *ipaddr, uint16_t port)
{
    wgd_tstate_t *ts = (wgd_tstate_t *) device;
    line_t       *line;
    bool          sent;

    wireguarddeviceStateUnlock(ts);
    line = wireguarddeviceEnsureTransportLine(ts, getWID());
    if (line == NULL)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), q);
        wireguarddeviceStateLock(ts);
        return ERR_CONN;
    }

    addresscontextSetIpPortProtocol(lineGetDestinationAddressContext(line), ipaddr, port, IP_PROTO_UDP);
    sent = wireguarddeviceForwardTransportPacket(ts, line, q);
    wireguarddeviceStateLock(ts);
    return sent ? ERR_OK : ERR_CONN;
    // return udpSendTo(device->udp_pcb, q, ipaddr, port);
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

static err_t wireguardifLookupPeer(wireguard_device_t *device, uint8_t peer_index, wireguard_peer_t **out);

err_t wireguardifAddPeer(wireguard_device_t *device, wireguard_peer_init_data_t *p, uint8_t *peer_index)
{
    assert(p != NULL);

    err_t             result;
    uint8_t           public_key[WIREGUARD_PUBLIC_KEY_LEN] = {0};
    size_t            public_key_len = sizeof(public_key);
    wireguard_peer_t *peer           = NULL;

    if (stringLength((const char *) p->public_key) != BASE64_ENCODE_OUT_SIZE(public_key_len))
    {
        return ERR_ARG;
    }

    if (wwBase64Decode((const char *) p->public_key, (unsigned int) stringLength((const char *) p->public_key),
                       public_key) != WIREGUARD_PUBLIC_KEY_LEN)
    {
        wCryptoZero(public_key, sizeof(public_key));
        return ERR_ARG;
    }

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
                if (! peerAddIp(peer, p->allowed_ip, p->allowed_mask))
                {
                    wCryptoZero(peer, sizeof(*peer));
                    peer->valid = false;
                    result = ERR_MEM;
                }
                else
                {
                    memoryCopy(peer->greatest_timestamp, p->greatest_timestamp, sizeof(peer->greatest_timestamp));
                    result = ERR_OK;
                }
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
    wCryptoZero(public_key, sizeof(public_key));
    return result;
}

err_t wireguardifAddAllowedIp(wireguard_device_t *device, uint8_t peer_index, const ip_addr_t *ip, const ip_addr_t *mask)
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
    sbuf_t *empty_buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(getWID()));
    if (empty_buf != NULL)
    {
        wireguardifOutputToPeer(device, empty_buf, NULL, peer);
    }
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
