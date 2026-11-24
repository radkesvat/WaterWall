#include "peer_store.h"

#include "loggers/network_logger.h"

static sbuf_t *wireguardCommonCreateiateHandshake(wireguard_device_t *device, wireguard_peer_t *peer,
                                                  message_handshake_initiation_t *msg, err_t *error)
{
    sbuf_t *buf = NULL;
    err_t   err = ERR_OK;
    if (wireguardCreateHandshakeInitiation(device, peer, msg))
    {
        // Send this packet out!
        buf = bufferpoolGetSmallBuffer(getCurrentWorkerBufferPool());
        sbufWrite(buf, msg, sizeof(message_handshake_initiation_t));
        sbufSetLength(buf, sizeof(message_handshake_initiation_t));
    }
    else
    {
        err = ERR_ARG;
    }
    if (error)
    {
        *error = err;
    }
    return buf;
}

static void armInitiationRateLimit(wireguard_peer_t *peer, uint32_t now)
{
    peer->last_initiation_tx     = now;
    peer->initiation_interval_ms = REKEY_TIMEOUT * 1000U + fastRandRange32(0, REKEY_TIMEOUT_JITTER_MS);
}

static bool handshakeAttemptExpired(const wireguard_peer_t *peer, uint32_t now)
{
    return now - peer->handshake_attempt_millis >= REKEY_ATTEMPT_TIME * 1000U;
}

static bool wireguardifCanSendInitiation(const wireguard_peer_t *peer, uint32_t now)
{
    /* Give the responder's newly issued response time for a cookie or key confirmation. */
    if (peer->next_keypair.valid && now - peer->next_keypair.keypair_millis < REKEY_TIMEOUT * 1000U)
        return false;
    return now - peer->last_initiation_tx >= peer->initiation_interval_ms;
}

static err_t sendInitiation(wireguard_device_t *device, wireguard_peer_t *peer, sbuf_t *packet)
{
    /* Authorization and packet preparation can outlast the attempt on this same loop iteration. */
    const uint32_t now = getTickMS();
    if (handshakeAttemptExpired(peer, now))
    {
        reuseBuffer(packet);
        return ERR_TIMEOUT;
    }
    armInitiationRateLimit(peer, now);
    return wireguardifPeerOutput(device, packet, peer, false);
}

static err_t startHandshake(wireguard_device_t *device, wireguard_peer_t *peer, bool force)
{
    err_t                          result;
    sbuf_t                        *buf;
    message_handshake_initiation_t msg;

    const uint32_t now = getTickMS();
    if ((! force) && (! wireguardifCanSendInitiation(peer, now)))
    {
        return ERR_WOULDBLOCK;
    }

    if (device->callbacks.can_initiate != NULL &&
        (! device->callbacks.can_initiate(device->context, peer) || ! peer->valid))
    {
        peer->retry_handshake        = false;
        peer->send_handshake         = false;
        peer->unanswered_interval_ms = 0;
        return ERR_CONN;
    }

    if (! peer->retry_handshake || (force && handshakeAttemptExpired(peer, now)))
        peer->handshake_attempt_millis = now;
    peer->retry_handshake        = true;
    peer->send_handshake         = false;
    peer->unanswered_interval_ms = 0;

    LOGD("Preparing handshake initiation for peer %s", ipAddrNetworkToAddress(&peer->ip));
    buf = wireguardCommonCreateiateHandshake(device, peer, &msg, &result);
    if (buf)
    {
        if (LIKELY(wireguardStorePendingHandshake(peer, &msg, sizeof(msg))))
            return sendInitiation(device, peer, buf);
        reuseBuffer(buf);
        result = ERR_ARG;
    }
    /* Throttle unsuccessful creation as well as normal transmissions. */
    armInitiationRateLimit(peer, getTickMS());
    return result;
}

err_t wireguardifStartHandshake(wireguard_device_t *device, wireguard_peer_t *peer, bool force)
{
    wireguardBeginProcessing(device);
    const err_t result = startHandshake(device, peer, force);
    wireguardEndProcessing(device);
    return result;
}

static err_t retryHandshake(wireguard_device_t *device, wireguard_peer_t *peer)
{
    wireguard_pending_handshake_t pending;
    sbuf_t                       *buf;
    err_t                         result;

    if (peer == NULL || ! peer->pending_handshake.valid)
    {
        return ERR_ARG;
    }

    pending = peer->pending_handshake;
    if (wireguardGetMessageType(pending.packet, pending.packet_len) != pending.message_type || pending.sender == 0 ||
        (pending.message_type != MESSAGE_HANDSHAKE_INITIATION && pending.message_type != MESSAGE_HANDSHAKE_RESPONSE))
    {
        return ERR_ARG;
    }

    const bool initiation = pending.message_type == MESSAGE_HANDSHAKE_INITIATION;
    if (initiation)
    {
        if (! peer->retry_handshake)
            return ERR_TIMEOUT;
        if (device->callbacks.can_initiate != NULL &&
            (! device->callbacks.can_initiate(device->context, peer) || ! peer->valid))
            return ERR_CONN;
    }
    buf = bufferpoolGetSmallBuffer(getCurrentWorkerBufferPool());
    sbufWrite(buf, pending.packet, pending.packet_len);
    sbufSetLength(buf, pending.packet_len);
    result = initiation ? sendInitiation(device, peer, buf) : wireguardifPeerOutput(device, buf, peer, false);
    return result;
}

err_t wireguardifRetryHandshake(wireguard_device_t *device, wireguard_peer_t *peer)
{
    wireguardBeginProcessing(device);
    const err_t result = retryHandshake(device, peer);
    wireguardEndProcessing(device);
    return result;
}

void wireguardCommonRequestHandshake(wireguard_device_t *device, wireguard_peer_t *peer)
{
    peer->handshake_attempt_millis = getTickMS();
    peer->retry_handshake          = true;
    peer->send_handshake           = true;
    wireguardifStartHandshake(device, peer, false);
}

static bool needsHandshakeInitiation(wireguard_peer_t *peer)
{
    /* A key reaching its threshold during an outstanding attempt joins that attempt's retry budget. */
    if (peer->curr_keypair.valid && ! peer->curr_keypair.initiator)
        wireguardRequestRekeyAtAge(peer, &peer->curr_keypair, REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT);
    if (peer->retry_handshake && handshakeAttemptExpired(peer, getTickMS()))
    {
        peer->retry_handshake = false;
        peer->send_handshake  = false;
    }
    const bool unanswered = peer->unanswered_interval_ms != 0 &&
                            wireguardRecoveryNow() - peer->unanswered_millis >= peer->unanswered_interval_ms;
    return peer->retry_handshake || peer->send_handshake || unanswered || (! peer->curr_keypair.valid && peer->active);
}

static bool shouldSendKeepalive(wireguard_peer_t *peer)
{
    const uint32_t now = wireguardRecoveryNow();
    const bool passive = peer->passive_keepalive && now - peer->passive_keepalive_millis >= KEEPALIVE_TIMEOUT * 1000U;
    const bool persistent = peer->keepalive_interval > 0 && now - peer->last_tx >= peer->keepalive_interval * 1000U;
    return (passive || persistent) && wireguardCommonPeerCanSend(peer);
}

static bool shouldDestroyKeypair(const wireguard_keypair_t *keypair)
{
    return keypair->valid && (wireguardExpired(keypair->keypair_millis, REJECT_AFTER_TIME) ||
                              keypair->sending_counter >= REJECT_AFTER_MESSAGES);
}

static bool shouldResetPeer(wireguard_peer_t *peer)
{
    bool result = false;
    if (peer->session_erase_armed && wireguardExpired(peer->session_erase_millis, REJECT_AFTER_TIME * 3))
    {
        result = true;
    }
    return result;
}

void wireguardCommonLoop(wireguard_device_t *device)
{
    wireguardBeginProcessing(device);
    bool link_up = false;
    for (wireguard_peer_t *peer = device->first_peer; peer != NULL; peer = peer->next)
    {
        if (peer->valid)
        {
            // Do we need to rekey / send a handshake?
            if (shouldResetPeer(peer))
            {
                // Nothing back for too long - we should wipe out all crypto state
                keypairDestroy(&peer->next_keypair);
                keypairDestroy(&peer->curr_keypair);
                keypairDestroy(&peer->prev_keypair);
                wireguardClearHandshakeState(peer);
                peer->session_erase_millis = 0;
                peer->session_erase_armed  = false;
                peer->passive_keepalive      = false;
                peer->unanswered_interval_ms = 0;
                /* A fresh demand can start a retry window shortly before secret erasure.
                 * Its next attempt creates fresh ephemeral state. */

                // Revert back to default IP/port if these were altered
                peer->ip   = peer->connect_ip;
                peer->port = peer->connect_port;
            }
            /* Each slot has its own lifetime. Preserve the separate deadline
             * for unfinished/pending handshake cleanup when a slot expires. */
            if (shouldDestroyKeypair(&peer->curr_keypair))
            {
                keypairDestroy(&peer->curr_keypair);
                wireguardPeerSyncReceivers(peer);
            }
            if (shouldDestroyKeypair(&peer->prev_keypair))
            {
                keypairDestroy(&peer->prev_keypair);
                wireguardPeerSyncReceivers(peer);
            }
            if (shouldDestroyKeypair(&peer->next_keypair))
            {
                keypairDestroy(&peer->next_keypair);
                wireguardPeerSyncReceivers(peer);
            }
            if (shouldSendKeepalive(peer))
            {
                wireguardifSendKeepalive(device, peer);
            }
            if (peer->valid && needsHandshakeInitiation(peer))
            {
                wireguardifStartHandshake(device, peer, false);
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
    wireguardEndProcessing(device);
}
