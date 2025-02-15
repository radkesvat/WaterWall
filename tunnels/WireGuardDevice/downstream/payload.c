#include "structure.h"

#include "loggers/network_logger.h"

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

static void wireguardifSendHandshakeCookie(wireguard_device_t *device, const uint8_t *mac1, uint32_t index,
                                           const ip_addr_t *addr, uint16_t port)
{
    message_cookie_reply_t packet;
    sbuf_t                *buf = NULL;
    uint8_t                source_buf[18];
    size_t                 source_len = getSourceAddrPort(addr, port, source_buf, sizeof(source_buf));

    wireguardCreateCookieReply(device, &packet, mac1, index, source_buf, source_len);

    // Send this packet out!
    buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(getWID()));

    sbufSetLength(buf, sizeof(message_cookie_reply_t));
    sbufWrite(buf, &packet, sizeof(message_cookie_reply_t));
    wireguardifDeviceOutput(device, buf, addr, port);
}

static void updatePeerAddr(wireguard_peer_t *peer, const ip_addr_t *addr, uint16_t port)
{
    peer->ip   = *addr;
    peer->port = port;
}

static void wireguardifProcessDataMessage(wireguard_device_t *device, wireguard_peer_t *peer,
                                          message_transport_data_t *data_hdr, size_t data_len, const ip_addr_t *addr,
                                          uint16_t port)
{
    wireguard_keypair_t *keypair;
    uint64_t             nonce;
    uint8_t             *src;
    uint32_t             src_len;
    sbuf_t              *buf = NULL;
    ip4_hdr_t           *iphdr;
    ip_addr_t            dest;
    bool                 dest_ok = false;
    int                  x;
    uint32_t             now;
    uint16_t             header_len = 0xFFFF;
    uint32_t             idx        = data_hdr->receiver;

    keypair = getPeerKeypairForIdx(peer, idx);

    if (keypair)
    {
        if ((keypair->receiving_valid) && ! wireguardExpired(keypair->keypair_millis, REJECT_AFTER_TIME) &&
            (keypair->sending_counter < REJECT_AFTER_MESSAGES)

        )
        {

            nonce   = U8TO64_LITTLE(data_hdr->counter);
            src     = &data_hdr->enc_packet[0];
            src_len = (uint32_t) data_len;

            // We don't know the unpadded size until we have decrypted the packet and validated/inspected the IP header
            buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(getWID()));
            if (buf)
            {
                // Decrypt the packet
                sbufSetLength(buf, src_len - WIREGUARD_AUTHTAG_LEN);
                sbufWriteZeros(buf, sbufGetBufLength(buf));
                if (wireguardDecryptPacket(sbufGetMutablePtr(buf), src, src_len, nonce, keypair))
                {

                    // 3. Since the packet has authenticated correctly, the source IP of the outer UDP/IP packet is used
                    // to update the endpoint for peer TrMv...WXX0. Update the peer location
                    updatePeerAddr(peer, addr, port);

                    now              = getTickMS();
                    keypair->last_rx = now;
                    peer->last_rx    = now;

                    // Might need to shuffle next key --> current keypair
                    keypairUpdate(peer, keypair);

                    // Check to see if we should rekey
                    if (keypair->initiator &&
                        wireguardExpired(keypair->keypair_millis,
                                         REJECT_AFTER_TIME - peer->keepalive_interval - REKEY_TIMEOUT))
                    {
                        peer->send_handshake = true;
                    }

                    // Make sure that link is reported as up
                    device->status_connected = true;

                    if (sbufGetBufLength(buf) > 0)
                    {
                        // 4a. Once the packet payload is decrypted, the interface has a plaintext packet. If this is
                        // not an IP packet, it is dropped.
                        iphdr = (ip4_hdr_t *) sbufGetMutablePtr(buf);
                        // Check for packet replay / dupes
                        if (wireguardCheckReplay(keypair, nonce))
                        {

                            // 4b. Otherwise, WireGuard checks to see if the source IP address of the plaintext
                            // inner-packet routes correspondingly in the cryptokey routing table Also check packet
                            // length!
#if LWIP_IPV4
                            if (IPH_V(iphdr) == 4)
                            {
                                ipAddrCopyFromIp4(dest, iphdr->dest);
                                for (x = 0; x < WIREGUARD_MAX_SRC_IPS; x++)
                                {
                                    if (peer->allowed_source_ips[x].valid)
                                    {
                                        if (ip4AddrNetcmp(ip_2_ip4(&dest), ip_2_ip4(&peer->allowed_source_ips[x].ip),
                                                          ip_2_ip4(&peer->allowed_source_ips[x].mask)))
                                        {
                                            dest_ok    = true;
                                            header_len = PP_NTOHS(IPH_LEN(iphdr));
                                            break;
                                        }
                                    }
                                }
                            }
#endif /* LWIP_IPV4 */
#if LWIP_IPV6
                            if (IPH_V(iphdr) == 6)
                            {
                                // TODO: IPV6 support for route filtering
                                header_len = PP_NTOHS(IPH_LEN(iphdr));
                                dest_ok    = true;
                            }
#endif /* LWIP_IPV6 */
                            if (header_len <= sbufGetBufLength(buf))
                            {

                                // 5. If the plaintext packet has not been dropped, it is inserted into the receive
                                // queue of the wg0 interface.
                                if (dest_ok)
                                {
                                    // Send packet to be process by LWIP
                                    // ip_input(buf, device->ts);

                                    wgd_tstate_t *ts     = (wgd_tstate_t *) device;
                                    if (ts->locked)
                                    {
                                        ts->locked = false;
                                        mutexUnlock(&ts->mutex);
                                    }
                                    tunnel_t     *tunnel = ts->tunnel;
                                    line_t       *line   = tunnelchainGetPacketLine(tunnel->chain, getWID());
                                    tunnelPrevDownStreamPayload(tunnel, line, buf);

                                    // buf is owned by IP layer now
                                    buf = NULL;
                                }
                            }
                            else
                            {
                                // IP header is corrupt or lied about packet size
                            }
                        }
                        else
                        {
                            // This is a duplicate packet / replayed / too far out of order
                        }
                    }
                    else
                    {
                        // This was a keep-alive packet
                        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
                        buf = NULL;
                    }
                }
                else
                {
                    bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
                    buf = NULL;
                }
            }
        }
        else
        {
            // After Reject-After-Messages transport data messages or after the current secure session is Reject-
            // After-Time seconds old,
            //  whichever comes first, WireGuard will refuse to send or receive any more transport data messages using
            //  the current secure session, until a new secure session is created through the 1-RTT handshake
            keypairDestroy(keypair);
        }
    }
    else
    {
        // Could not locate valid keypair for remote index
    }
    if (buf != NULL)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), buf);
    }
}

static void wireguardifProcessResponseMessage(wireguard_device_t *device, wireguard_peer_t *peer,
                                              message_handshake_response_t *response, const ip_addr_t *addr,
                                              uint16_t port)
{
    if (wireguardProcessHandshakeResponse(device, peer, response))
    {
        // Packet is good
        // Update the peer location
        updatePeerAddr(peer, addr, port);

        wireguardStartSession(peer, true);
        wireguardifSendKeepalive(device, peer);

        // Set the IF-UP flag on ts
        device->status_connected = 1;
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

        wireguardStartSession(peer, false);

        // Send this packet out!
        buf = bufferpoolGetSmallBuffer(getWorkerBufferPool(getWID()));

        if (buf)
        {
            sbufSetLength(buf, sizeof(message_handshake_response_t));

            sbufWrite(buf, &packet, sizeof(message_handshake_response_t));
            // OK!
            wireguardifPeerOutput(device, buf, peer);
        }
    }
}

static bool wireguardifCheckResponseMessage(wireguard_device_t *device, message_handshake_response_t *msg,
                                            const ip_addr_t *addr, uint16_t port)
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
            source_len = getSourceAddrPort(addr, port, source_buf, sizeof(source_buf));

            result = wireguardCheckMac2(device, data, sizeof(message_handshake_response_t) - (WIREGUARD_COOKIE_LEN),
                                        source_buf, source_len, msg->mac2);

            if (! result)
            {
                // mac2 is invalid (cookie may have expired) or not present
                // 5.3 Denial of Service Mitigation & Cookies
                // If the responder receives a message with a valid msg.mac1 yet with an invalid msg.mac2, and is under
                // load, it may respond with a cookie reply message
                wireguardifSendHandshakeCookie(device, msg->mac1, msg->sender, addr, port);
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
                                              const ip_addr_t *addr, uint16_t port)
{
    bool     result = false;
    uint8_t *data   = (uint8_t *) msg;
    uint8_t  source_buf[18];
    size_t   source_len;
    // We received an initiation packet check it is valid

    if (wireguardCheckMac1(device, data, sizeof(message_handshake_initiation_t) - (2 * WIREGUARD_COOKIE_LEN),
                           msg->mac1))
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
            source_len = getSourceAddrPort(addr, port, source_buf, sizeof(source_buf));

            result = wireguardCheckMac2(device, data, sizeof(message_handshake_initiation_t) - (WIREGUARD_COOKIE_LEN),
                                        source_buf, source_len, msg->mac2);

            if (! result)
            {
                // mac2 is invalid (cookie may have expired) or not present
                // 5.3 Denial of Service Mitigation & Cookies
                // If the responder receives a message with a valid msg.mac1 yet with an invalid msg.mac2, and is under
                // load, it may respond with a cookie reply message
                wireguardifSendHandshakeCookie(device, msg->mac1, msg->sender, addr, port);
            }
        }
    }
    else
    {
        // mac1 is invalid
    }
    return result;
}

static void wireguardifNetworkRx(wireguard_device_t *device, sbuf_t *p, const ip_addr_t *addr, uint16_t port)
{
    assert(device != NULL);
    assert(p != NULL);
    // We have received a packet from the base_netif to our UDP port - process this as a possible Wireguard packet
    wireguard_peer_t *peer;
    uint8_t          *data = sbufGetMutablePtr(p);
    size_t            len  = sbufGetBufLength(p); // This buf, not chained ones

    message_handshake_initiation_t *msg_initiation;
    message_handshake_response_t   *msg_response;
    message_cookie_reply_t         *msg_cookie;
    message_transport_data_t       *msg_data;

    uint8_t type = wireguardGetMessageType(data, len);

    switch (type)
    {
    case MESSAGE_HANDSHAKE_INITIATION:
        msg_initiation = (message_handshake_initiation_t *) data;

        // Check mac1 (and optionally mac2) are correct - note it may internally generate a cookie reply pack
        // t
        if (wireguardifCheckInitiationMessage(device, msg_initiation, addr, port))
        {

            peer = wireguardProcessInitiationMessage(device, msg_initiation);
            if (peer)
            {
                // Update the peer location
                updatePeerAddr(peer, addr, port);

                // Send back a handshake response
                wireguardifSendHandshakeResponse(device, peer);
            }
        }
        break;

    case MESSAGE_HANDSHAKE_RESPONSE:
        msg_response = (message_handshake_response_t *) data;

        // Check mac1 (and optionally mac2) are correct - note it may internally generate a cookie reply packet
        if (wireguardifCheckResponseMessage(device, msg_response, addr, port))
        {

            peer = peerLookupByHandshake(device, msg_response->receiver);
            if (peer)
            {
                // Process the handshake response
                wireguardifProcessResponseMessage(device, peer, msg_response, addr, port);
            }
        }
        break;

    case MESSAGE_COOKIE_REPLY:
        msg_cookie = (message_cookie_reply_t *) data;
        peer       = peerLookupByHandshake(device, msg_cookie->receiver);
        if (peer)
        {
            if (wireguardProcessCookieMessage(device, peer, msg_cookie))
            {
                // Update the peer location
                updatePeerAddr(peer, addr, port);

                // Don't send anything out - we stay quiet until the next initiation message
            }
        }
        break;

    case MESSAGE_TRANSPORT_DATA:
        msg_data = (message_transport_data_t *) data;
        peer     = peerLookupByReceiver(device, msg_data->receiver);
        if (peer)
        {
            // header is 16 bytes long so take that off the length
            wireguardifProcessDataMessage(device, peer, msg_data, len - 16, addr, port);
        }
        break;

    default:
        // Unknown or bad packet header
        break;
    }
    // Release data!
    bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), p);
}

void wireguarddeviceTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    wgd_tstate_t *state = tunnelGetState(t);
    mutexLock(&state->mutex);
    state->locked = true;

    wireguardifNetworkRx((wireguard_device_t *) tunnelGetState(t), buf, &l->routing_context.src_ctx.ip_address,
                         l->routing_context.src_ctx.port);

    if (state->locked)
    {
        state->locked = false;
        mutexUnlock(&state->mutex);
    }
    mutexUnlock(&state->mutex);
}
