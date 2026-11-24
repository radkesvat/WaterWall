#include "peer_store.h"

#include "loggers/network_logger.h"

typedef struct receive_source_s
{
    const ip_addr_t *ip;
    uint16_t         port;
    uint64_t         carrier_id;
} receive_source_t;

static size_t getSourceAddrPort(const ip_addr_t *addr, uint16_t port, uint8_t *buf, size_t buflen)
{
    size_t result = 0;

#if LWIP_IPV4
    if (IP_IS_V4(addr) && (buflen >= 4))
    {
        U32TO8_BIG(buf + result, PP_NTOHL(ip4AddrGetU32(ip_2_ip4(addr))));
        result += 4;
    }
#endif
#if LWIP_IPV6
    if (IP_IS_V6(addr) && (buflen >= 16))
    {
        U16TO8_BIG(buf + result + 0, IP6_ADDR_BLOCK1(ip_2_ip6(addr)));
        U16TO8_BIG(buf + result + 2, IP6_ADDR_BLOCK2(ip_2_ip6(addr)));
        U16TO8_BIG(buf + result + 4, IP6_ADDR_BLOCK3(ip_2_ip6(addr)));
        U16TO8_BIG(buf + result + 6, IP6_ADDR_BLOCK4(ip_2_ip6(addr)));
        U16TO8_BIG(buf + result + 8, IP6_ADDR_BLOCK5(ip_2_ip6(addr)));
        U16TO8_BIG(buf + result + 10, IP6_ADDR_BLOCK6(ip_2_ip6(addr)));
        U16TO8_BIG(buf + result + 12, IP6_ADDR_BLOCK7(ip_2_ip6(addr)));
        U16TO8_BIG(buf + result + 14, IP6_ADDR_BLOCK8(ip_2_ip6(addr)));
        result += 16;
    }
#endif
    if (buflen >= result + 2)
    {
        U16TO8_BIG(buf + result, port);
        result += 2;
    }
    return result;
}

static size_t getCookieSource(const receive_source_t *source, uint8_t *buf, size_t buflen)
{
    if (source->ip != NULL)
        return getSourceAddrPort(source->ip, source->port, buf, buflen);

    assert(source->carrier_id != 0 && buflen >= 9);
    /* A tagged carrier identity is distinct from the 6/18-byte network
     * identities. It identifies a channel, never a synthetic IP endpoint. */
    buf[0] = 1;
    U64TO8_LITTLE(buf + 1, source->carrier_id);
    return 9;
}

static void wireguardifSendHandshakeCookie(wireguard_device_t *device, const uint8_t *mac1, uint32_t index,
                                           const receive_source_t *source)
{
    message_cookie_reply_t packet;
    sbuf_t                *buf = NULL;
    uint8_t                source_buf[18];
    size_t                 source_len = getCookieSource(source, source_buf, sizeof(source_buf));

    if (UNLIKELY(! wireguardCreateCookieReply(device, &packet, mac1, index, source_buf, source_len)))
    {
        LOGW("WireGuard: failed to create secure handshake cookie reply");
        return;
    }

    // Send this packet out!
    buf = bufferpoolGetSmallBuffer(getCurrentWorkerBufferPool());
    sbufSetLength(buf, sizeof(message_cookie_reply_t));
    sbufWrite(buf, &packet, sizeof(message_cookie_reply_t));
    wireguardifDeviceOutput(device, buf, source->ip, source->port);
}

static bool updatePeerAddr(wireguard_device_t *device, wireguard_peer_t *peer, const receive_source_t *source)
{
    if (device->callbacks.authenticated != NULL && ! device->callbacks.authenticated(device->context, peer))
        return false;
    if (! peer->valid)
        return false;
    ++peer->authenticated_receives;
    peer->unanswered_interval_ms = 0;
    if (source->ip != NULL)
    {
        peer->ip   = *source->ip;
        peer->port = source->port;
    }
    return true;
}

static bool wireguardCommonGetPlaintextPacketMetadata(const sbuf_t *buf, ip_addr_t *source, uint16_t *packet_len)
{
    const uint8_t *data = sbufGetRawPtr(buf);
    uint32_t       len  = sbufGetLength(buf);
    uint8_t        version;

    if (UNLIKELY(len < sizeof(ip4_hdr_t)))
    {
        return false;
    }

    version = IP_HDR_GET_VERSION(data);

    if (version == 4)
    {
        const ip4_hdr_t *iphdr          = (const ip4_hdr_t *) data;
        uint16_t         total_len      = PP_NTOHS(IPH_LEN(iphdr));
        uint16_t         minimum_header = (uint16_t) (IPH_HL_BYTES(iphdr));

        if (UNLIKELY((minimum_header < sizeof(ip4_hdr_t)) || (total_len < minimum_header) || (total_len > len)))
        {
            return false;
        }

        ipAddrCopyFromIp4(*source, iphdr->src);
        *packet_len = total_len;
        return true;
    }

    if (version == 6)
    {
        if (UNLIKELY(len < sizeof(ip6_hdr_t)))
        {
            return false;
        }

        const ip6_hdr_t *ip6hdr = (const ip6_hdr_t *) data;
        ip6_addr_t       src_addr;
        uint16_t         total_len = (uint16_t) (sizeof(ip6_hdr_t) + PP_NTOHS(ip6hdr->_plen));

        if (UNLIKELY((total_len < sizeof(ip6_hdr_t)) || (total_len > len)))
        {
            return false;
        }

        memoryCopy(&src_addr, &ip6hdr->src, sizeof(src_addr));
        ipAddrCopyFromIp6(*source, src_addr);
        *packet_len = total_len;
        return true;
    }

    return false;
}

sbuf_t *wireguardCommonDecrypt(buffer_pool_t *pool, const uint8_t *ciphertext, uint32_t ciphertext_len, uint64_t nonce,
                               wireguard_keypair_t *keypair)
{
    assert(pool != NULL);
    assert(ciphertext != NULL);
    assert(keypair != NULL);

    if (UNLIKELY(ciphertext_len < WIREGUARD_AUTHTAG_LEN))
    {
        return NULL;
    }

    const uint32_t plaintext_len = ciphertext_len - WIREGUARD_AUTHTAG_LEN;
    sbuf_t        *buf           = bufferpoolGetBestFit(pool, plaintext_len, bufferpoolGetLargeBufferPadding(pool));

    if (UNLIKELY(sbufGetWritableCapacity(buf) < plaintext_len))
    {
        LOGF("WireGuard: best-fit decryption buffer has %zu writable bytes for a %u-byte plaintext",
             sbufGetWritableCapacity(buf),
             (unsigned int) plaintext_len);
        abortProgramNow(1);
    }

    if (UNLIKELY(! wireguardDecryptPacket(
            sbufGetMutablePtr(buf), sbufGetWritableCapacity(buf), ciphertext, ciphertext_len, nonce, keypair)))
    {
        bufferpoolReuseBuffer(pool, buf);
        return NULL;
    }

    sbufSetLength(buf, plaintext_len);
    return buf;
}

static void wireguardifProcessDataMessage(wireguard_device_t *device, wireguard_peer_t *peer,
                                          message_transport_data_t *data_hdr, uint32_t data_len,
                                          const receive_source_t *receive_source)
{
    wireguard_keypair_t *keypair;
    uint64_t             nonce;
    uint8_t             *src;
    sbuf_t              *buf = NULL;
    ip_addr_t            source;
    uint16_t             packet_len = 0;
    uint32_t             idx        = data_hdr->receiver;

    keypair = getPeerKeypairForIdx(peer, idx);
    assert(keypair != NULL);

    nonce = U8TO64_LITTLE(data_hdr->counter);
    src   = &data_hdr->enc_packet[0];

    if (UNLIKELY(! keypair->receiving_valid || wireguardExpired(keypair->keypair_millis, REJECT_AFTER_TIME)))
    {
        // Reject-After-Time has passed for this keypair. Drop this packet and force a new handshake.
        keypairDestroy(keypair);
        wireguardPeerSyncReceivers(peer);
        goto finish;
    }

    if (UNLIKELY(nonce >= REJECT_AFTER_MESSAGES))
    {
        goto finish;
    }

    buf = wireguardCommonDecrypt(getCurrentWorkerBufferPool(), src, data_len, nonce, keypair);
    if (LIKELY(buf != NULL))
    {
        if (UNLIKELY(! wireguardCheckReplay(keypair, nonce)))
        {
            goto finish;
        }

        // Authenticated network input can update the peer endpoint. Connected
        // carrier input keeps routing with its carrier instead.
        if (! updatePeerAddr(device, peer, receive_source))
            goto finish;

        keypair->sending_valid = true;

        if (UNLIKELY(peer->pending_handshake.valid &&
                     peer->pending_handshake.message_type == MESSAGE_HANDSHAKE_RESPONSE &&
                     peer->pending_handshake.sender == idx))
        {
            wireguardClearPendingHandshake(peer);
        }

        if (keypair == &peer->next_keypair)
        {
            peer->retry_handshake = false;
            peer->send_handshake  = false;
        }

        // Might need to shuffle next key --> current keypair
        keypairUpdate(peer, keypair);
        keypair = getPeerKeypairForIdx(peer, idx);
        assert(keypair != NULL);

        // Make sure that link is reported as up
        device->status_connected = true;

        // Check to see if we should rekey
        if (keypair->initiator)
            wireguardRequestRekeyAtAge(peer, keypair, REJECT_AFTER_TIME - KEEPALIVE_TIMEOUT - REKEY_TIMEOUT);

        if (sbufGetLength(buf) > 0)
        {
            if (! peer->passive_keepalive)
            {
                peer->passive_keepalive        = true;
                peer->passive_keepalive_millis = wireguardRecoveryNow();
            }
            if (wireguardCommonGetPlaintextPacketMetadata(buf, &source, &packet_len) &&
                wireguardCommonPeerAllowsIp(peer, &source))
            {
                sbufSetLength(buf, packet_len);
                device->callbacks.inner(device->context, buf, peer);

                // buf is owned by previous packet layer now
                buf = NULL;
            }
        }
        else
        {
            // This was a keep-alive packet
            reuseBuffer(buf);
            buf = NULL;
        }
    }
finish:
    if (buf != NULL)
    {
        reuseBuffer(buf);
    }
}

static void wireguardifProcessResponseMessage(wireguard_device_t *device, wireguard_peer_t *peer,
                                              message_handshake_response_t *response, const receive_source_t *source)
{
    if (wireguardProcessHandshakeResponse(device, peer, response))
    {
        // Packet is good
        // Update the peer location
        if (! updatePeerAddr(device, peer, source))
            return;

        if (UNLIKELY(! wireguardStartSession(peer, true)))
        {
            LOGW("WireGuard: failed to derive transport session keys");
            return;
        }
        wireguardClearPendingHandshake(peer);
        peer->retry_handshake = false;
        peer->send_handshake  = false;
        // Set the IF-UP flag on ts
        device->status_connected = 1;
        wireguardifSendKeepalive(device, peer);
    }
    else
    {
        // Packet bad
    }
}

static void wireguardifSendHandshakeResponse(wireguard_device_t *device, wireguard_peer_t *peer)
{
    message_handshake_response_t packet;
    sbuf_t                      *buf = NULL;

    if (wireguardCreateHandshakeResponse(device, peer, &packet))
    {

        if (UNLIKELY(! wireguardStartSession(peer, false)))
        {
            LOGW("WireGuard: failed to derive responder transport keys");
            return;
        }

        // Send this packet out!
        buf = bufferpoolGetSmallBuffer(getCurrentWorkerBufferPool());

        if (UNLIKELY(! wireguardStorePendingHandshake(peer, &packet, sizeof(packet))))
        {
            reuseBuffer(buf);
            LOGW("WireGuard: failed to retain outbound handshake response");
            return;
        }

        sbufSetLength(buf, sizeof(message_handshake_response_t));

        sbufWrite(buf, &packet, sizeof(message_handshake_response_t));
        // OK!
        wireguardifPeerOutput(device, buf, peer, false);
    }
}

static bool wireguardifCheckResponseMessage(wireguard_device_t *device, message_handshake_response_t *msg,
                                            const receive_source_t *source)
{
    bool     result = false;
    uint8_t *data   = (uint8_t *) msg;
    uint8_t  source_buf[18];
    size_t   source_len;
    // We received an initiation packet check it is valid

    if (wireguardCheckMac1(device, data, sizeof(message_handshake_response_t) - (2 * WIREGUARD_COOKIE_LEN), msg->mac1))
    {
        // mac1 is valid!
        if (! isSystemUnderLoad(SYSTEM_LOAD_THRESHOULD))
        {
            // If we aren't under load we only need mac1 to be correct
            result = true;
        }
        else
        {
            // If we are under load then check mac2
            source_len = getCookieSource(source, source_buf, sizeof(source_buf));

            result = wireguardCheckMac2(device,
                                        data,
                                        sizeof(message_handshake_response_t) - (WIREGUARD_COOKIE_LEN),
                                        source_buf,
                                        source_len,
                                        msg->mac2);

            if (! result)
            {
                // mac2 is invalid (cookie may have expired) or not present
                // 5.3 Denial of Service Mitigation & Cookies
                // If the responder receives a message with a valid msg.mac1 yet with an invalid msg.mac2, and is under
                // load, it may respond with a cookie reply message
                wireguardifSendHandshakeCookie(device, msg->mac1, msg->sender, source);
            }
        }
    }
    else
    {
        // mac1 is invalid
    }
    return result;
}

static bool wireguardifCheckInitiationMessage(wireguard_device_t *device, message_handshake_initiation_t *msg,
                                              const receive_source_t *source)
{
    bool     result = false;
    uint8_t *data   = (uint8_t *) msg;
    uint8_t  source_buf[18];
    size_t   source_len;
    // We received an initiation packet check it is valid

    if (wireguardCheckMac1(
            device, data, sizeof(message_handshake_initiation_t) - (2 * WIREGUARD_COOKIE_LEN), msg->mac1))
    {
        // mac1 is valid!
        if (! isSystemUnderLoad(SYSTEM_LOAD_THRESHOULD))
        {
            // If we aren't under load we only need mac1 to be correct
            result = true;
        }
        else
        {
            // If we are under load then check mac2
            source_len = getCookieSource(source, source_buf, sizeof(source_buf));

            result = wireguardCheckMac2(device,
                                        data,
                                        sizeof(message_handshake_initiation_t) - (WIREGUARD_COOKIE_LEN),
                                        source_buf,
                                        source_len,
                                        msg->mac2);

            if (! result)
            {
                // mac2 is invalid (cookie may have expired) or not present
                // 5.3 Denial of Service Mitigation & Cookies
                // If the responder receives a message with a valid msg.mac1 yet with an invalid msg.mac2, and is under
                // load, it may respond with a cookie reply message
                wireguardifSendHandshakeCookie(device, msg->mac1, msg->sender, source);
            }
        }
    }
    else
    {
        // mac1 is invalid
    }
    return result;
}

static void receive(wireguard_device_t *device, sbuf_t *p, const receive_source_t *source)
{
    assert(device != NULL);
    assert(p != NULL);
    // Process one complete WireGuard datagram from a network endpoint or carrier.
    wireguard_peer_t *peer;
    uint8_t          *data = sbufGetMutablePtr(p);
    uint32_t          len  = sbufGetLength(p); // This buf, not chained ones

    message_handshake_initiation_t *msg_initiation;
    message_handshake_response_t   *msg_response;
    message_cookie_reply_t         *msg_cookie;
    message_transport_data_t       *msg_data;

    wireguardBeginProcessing(device);
    uint8_t type = wireguardGetMessageType(data, len);

    switch (type)
    {
    case MESSAGE_HANDSHAKE_INITIATION:
        msg_initiation = (message_handshake_initiation_t *) data;

        // Check mac1 (and optionally mac2) are correct - note it may internally generate a cookie reply pack
        // t
        if (wireguardifCheckInitiationMessage(device, msg_initiation, source))
        {

            peer = wireguardProcessInitiationMessage(device, msg_initiation);
            if (peer)
            {
                // Update the peer location
                if (! updatePeerAddr(device, peer, source))
                    break;

                // Send back a handshake response
                wireguardifSendHandshakeResponse(device, peer);
            }
        }
        break;

    case MESSAGE_HANDSHAKE_RESPONSE:
        msg_response = (message_handshake_response_t *) data;

        // Check mac1 (and optionally mac2) are correct - note it may internally generate a cookie reply packet
        if (wireguardifCheckResponseMessage(device, msg_response, source))
        {

            peer = peerLookupByHandshake(device, msg_response->receiver);
            if (peer)
            {
                // Process the handshake response
                wireguardifProcessResponseMessage(device, peer, msg_response, source);
            }
        }
        break;

    case MESSAGE_COOKIE_REPLY:
        msg_cookie = (message_cookie_reply_t *) data;
        peer       = peerLookupByPendingHandshake(device, msg_cookie->receiver);
        if (peer)
        {
            if (wireguardProcessCookieMessage(device, peer, msg_cookie))
            {
                // Update the peer location
                /* A cookie authenticates the responder cookie key, not a new carrier. */

                // Retry the exact initiation or response authenticated by this
                // cookie. A response cannot be replaced with a new initiation.
                const bool retry_response = peer->pending_handshake.message_type == MESSAGE_HANDSHAKE_RESPONSE;
                if (wireguardifRetryHandshake(device, peer) != ERR_OK && retry_response)
                    LOGW("WireGuard: failed to retransmit cookie-protected handshake response");
            }
        }
        break;

    case MESSAGE_TRANSPORT_DATA:
        msg_data = (message_transport_data_t *) data;
        peer     = peerLookupByReceiver(device, msg_data->receiver);
        if (peer)
        {
            wireguardifProcessDataMessage(
                device, peer, msg_data, len - (uint32_t) sizeof(message_transport_data_t), source);
        }
        break;

    default:
        // Unknown or bad packet header
        break;
    }
    wireguardEndProcessing(device);
    reuseBuffer(p);
}

void wireguardCommonReceive(wireguard_device_t *device, sbuf_t *packet, const ip_addr_t *ip, uint16_t port)
{
    assert(ip != NULL);
    const receive_source_t source = {.ip = ip, .port = port};
    receive(device, packet, &source);
}

void wireguardCommonReceiveOnCarrier(wireguard_device_t *device, sbuf_t *packet, uint64_t carrier_id)
{
    assert(carrier_id != 0);
    const receive_source_t source = {.carrier_id = carrier_id};
    receive(device, packet, &source);
}
