#include "structure.h"

static sbuf_t *wireguardifInitiateHandshake(wireguard_device_t *device, wireguard_peer_t *peer,
                                            message_handshake_initiation_t *msg, err_t *error)
{
    sbuf_t *pbuf = NULL;
    err_t   err  = ERR_OK;
    if (wireguardCreateHandshakeInitiation(device, peer, msg))
    {
        // Send this packet out!
        pbuf = pbufAlloc(sbuf_tRANSPORT, sizeof(message_handshake_initiation_t), PBUF_RAM);
        if (pbuf)
        {
            err = pbufTake(pbuf, msg, sizeof(message_handshake_initiation_t));
            if (err == ERR_OK)
            {
                // OK!
            }
            else
            {
                pbufFree(pbuf);
                pbuf = NULL;
            }
        }
        else
        {
            err = ERR_MEM;
        }
    }
    else
    {
        err = ERR_ARG;
    }
    if (error)
    {
        *error = err;
    }
    return pbuf;
}

static err_t wireguardStartHandshake(wgd_tstate_t *ts, wireguard_peer_t *peer)
{
    wireguard_device_t            *device = (wireguard_device_t *) ts->state;
    err_t                          result;
    sbuf_t                        *pbuf;
    message_handshake_initiation_t msg;

    pbuf = wireguardifInitiateHandshake(device, peer, &msg, &result);
    if (pbuf)
    {
        result = wireguardifPeerOutput(ts, pbuf, peer);
        pbufFree(pbuf);
        peer->send_handshake     = false;
        peer->last_initiation_tx = getTickMS();
        memcpy(peer->handshake_mac1, msg.mac1, WIREGUARD_COOKIE_LEN);
        peer->handshake_mac1_valid = true;
    }
    return result;
}

static void wireguardifSendKeepalive(wireguard_device_t *device, wireguard_peer_t *peer)
{
    // Send a NULL packet as a keep-alive
    wireguardifOutputToPeer(device->ts, NULL, NULL, peer);
}

static bool wireguardifCanSendInitiation(wireguard_peer_t *peer)
{
    return ((peer->last_initiation_tx == 0) || (wireguardExpired(peer->last_initiation_tx, REKEY_TIMEOUT)));
}

static bool shouldSendInitiation(wireguard_peer_t *peer)
{
    bool result = false;
    if (wireguardifCanSendInitiation(peer))
    {
        if (peer->send_handshake)
        {
            result = true;
        }
        else if (peer->curr_keypair.valid && ! peer->curr_keypair.initiator &&
                 wireguardExpired(peer->curr_keypair.keypair_millis, REJECT_AFTER_TIME - peer->keepalive_interval))
        {
            result = true;
        }
        else if (! peer->curr_keypair.valid && peer->active)
        {
            result = true;
        }
    }
    return result;
}

static bool shouldSendKeepalive(wireguard_peer_t *peer)
{
    bool result = false;
    if (peer->keepalive_interval > 0)
    {
        if ((peer->curr_keypair.valid) || (peer->prev_keypair.valid))
        {
            if (wireguardExpired(peer->last_tx, peer->keepalive_interval))
            {
                result = true;
            }
        }
    }
    return result;
}

static bool shouldDestroyCurrentKeypair(wireguard_peer_t *peer)
{
    bool result = false;
    if (peer->curr_keypair.valid && (wireguardExpired(peer->curr_keypair.keypair_millis, REJECT_AFTER_TIME) ||
                                     (peer->curr_keypair.sending_counter >= REJECT_AFTER_MESSAGES)))
    {
        result = true;
    }
    return result;
}

static bool shouldResetPeer(wireguard_peer_t *peer)
{
    bool result = false;
    if (peer->curr_keypair.valid && (wireguardExpired(peer->curr_keypair.keypair_millis, REJECT_AFTER_TIME * 3)))
    {
        result = true;
    }
    return result;
}

void wdevCycle(wgd_tstate_t *ts)
{
    wireguard_device_t *device = &(ts->wg_device);
    wireguard_peer_t   *peer;
    int                 x;

    // Check periodic things
    bool link_up = false;
    for (x = 0; x < WIREGUARD_MAX_PEERS; x++)
    {
        peer = &device->peers[x];
        if (peer->valid)
        {
            // Do we need to rekey / send a handshake?
            if (shouldResetPeer(peer))
            {
                // Nothing back for too long - we should wipe out all crypto state
                keypairDestroy(&peer->next_keypair);
                keypairDestroy(&peer->curr_keypair);
                keypairDestroy(&peer->prev_keypair);
                // TODO: Also destroy handshake?

                // Revert back to default IP/port if these were altered
                peer->ip   = peer->connect_ip;
                peer->port = peer->connect_port;
            }
            if (shouldDestroyCurrentKeypair(peer))
            {
                // Destroy current keypair
                keypairDestroy(&peer->curr_keypair);
            }
            if (shouldSendKeepalive(peer))
            {
                wireguardifSendKeepalive(device, peer);
            }
            if (shouldSendInitiation(peer))
            {
                wireguardStartHandshake(device->netif, peer);
            }

            if ((peer->curr_keypair.valid) || (peer->prev_keypair.valid))
            {
                link_up = true;
            }
        }
    }

    if (! link_up)
    {
        // Clear the IF-UP flag on netif
        device->status_connected = false;
    }
}
