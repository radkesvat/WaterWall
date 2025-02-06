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

#include "wireguardif.h"

#include <stdlib.h>
#include <string.h>

#include "lwip/ip.h"
#include "lwip/mem.h"
#include "lwip/netif.h"
#include "lwip/sys.h"
#include "lwip/timeouts.h"
#include "lwip/udp.h"

#include "crypto.h"
#include "wireguard.h"

#include <stdio.h> // TODO: Remove

#define WIREGUARDIF_TIMER_MSECS 400

static void updatePeerAddr(wireguard_peer_t *peer, const ip_addr_t *addr, u16_t port)
{
    peer->ip   = *addr;
    peer->port = port;
}

static wireguard_peer_t *peerLookupByAllowedIp(wireguard_device_t *device, const ip4_addr_t *ipaddr)
{
    wireguard_peer_t *result = NULL;
    wireguard_peer_t *tmp;
    int                    x;
    int                    y;
    for (x = 0; (! result) && (x < WIREGUARD_MAX_PEERS); x++)
    {
        tmp = &device->peers[x];
        if (tmp->valid)
        {
            for (y = 0; y < WIREGUARD_MAX_SRC_IPS; y++)
            {
                if ((tmp->allowed_source_ips[y].valid) &&
                    ip_addr_netcmp(ipaddr, &tmp->allowed_source_ips[y].ip, &tmp->allowed_source_ips[y].mask))
                {
                    result = tmp;
                    break;
                }
            }
        }
    }
    return result;
}

static bool wireguardifCanSendInitiation(wireguard_peer_t *peer)
{
    return ((peer->last_initiation_tx == 0) || (wireguard_expired(peer->last_initiation_tx, REKEY_TIMEOUT)));
}

static err_t wireguardifPeerOutput(netif_t *netif, pbuf_t *q, wireguard_peer_t *peer)
{
    wireguard_device_t *device = (wireguard_device_t *) netif->state;
    // Send to last know port, not the connect port
    // TODO: Support DSCP and ECN - lwip requires this set on PCB globally, not per packet
    return udp_sendto(device->udp_pcb, q, &peer->ip, peer->port);
}

static err_t wireguardifDeviceOutput(wireguard_device_t *device, pbuf_t *q, const ip4_addr_t *ipaddr,
                                       u16_t port)
{
    return udp_sendto(device->udp_pcb, q, ipaddr, port);
}

static err_t wireguardifOutputToPeer(netif_t *netif, pbuf_t *q, const ip4_addr_t *ipaddr,
                                        wireguard_peer_t *peer)
{
    // The LWIP IP layer wants to send an IP packet out over the interface - we need to encrypt and send it to the peer
    message_transport_data_t *hdr;
    pbuf_t                   *pbuf;
    err_t                          result;
    size_t                         unpadded_len;
    size_t                         padded_len;
    size_t                         header_len = 16;
    uint8_t                       *dst;
    uint32_t                       now;
    wireguard_keypair_t      *keypair = &peer->curr_keypair;

    // Note: We may not be able to use the current keypair if we haven't received data, may need to resort to using
    // previous keypair
    if (keypair->valid && (! keypair->initiator) && (keypair->last_rx == 0))
    {
        keypair = &peer->prev_keypair;
    }

    if (keypair->valid && (keypair->initiator || keypair->last_rx != 0))
    {

        if (! wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME) &&
            (keypair->sending_counter < REJECT_AFTER_MESSAGES))
        {

            // Calculate the outgoing packet size - round up to next 16 bytes, add 16 bytes for header
            if (q)
            {
                // This is actual transport data
                unpadded_len = q->tot_len;
            }
            else
            {
                // This is a keep-alive
                unpadded_len = 0;
            }
            padded_len = (unpadded_len + 15) & 0xFFFFFFF0; // Round up to next 16 byte boundary

            // The buffer needs to be allocated from "transport" pool to leave room for LwIP generated IP headers
            // The IP packet consists of 16 byte header (struct message_transport_data), data padded upto 16 byte
            // boundary + encrypted auth tag (16 bytes)
            pbuf = pbuf_alloc(PBUF_TRANSPORT, header_len + padded_len + WIREGUARD_AUTHTAG_LEN, PBUF_RAM);
            if (pbuf)
            {
                // Note: allocating pbuf from RAM above guarantees that the pbuf is in one section and not chained
                // - i.e payload points to the contiguous memory region
                memset(pbuf->payload, 0, pbuf->tot_len);

                hdr = (message_transport_data_t *) pbuf->payload;

                hdr->type     = MESSAGE_TRANSPORT_DATA;
                hdr->receiver = keypair->remote_index;
                // Alignment required... pbuf_alloc has probably aligned data, but want to be sure
                U64TO8_LITTLE(hdr->counter, keypair->sending_counter);

                // Copy the encrypted (padded) data to the output packet - chacha20poly1305_encrypt() can encrypt data
                // in-place which avoids call to mem_malloc
                dst = &hdr->enc_packet[0];
                if ((padded_len > 0) && q)
                {
                    // Note: before copying make sure we have inserted the IP header checksum
                    // The IP header checksum (and other checksums in the IP packet - e.g. ICMP) need to be calculated
                    // by LWIP before calling The Wireguard interface always needs checksums to be generated in software
                    // but the base netif may have some checksums generated by hardware

                    // Copy pbuf to memory - handles case where pbuf is chained
                    pbuf_copy_partial(q, dst, unpadded_len, 0);
                }

                // Then encrypt
                wireguard_encrypt_packet(dst, dst, padded_len, keypair);

                result = wireguardifPeerOutput(netif, pbuf, peer);

                if (result == ERR_OK)
                {
                    now              = wireguard_sys_now();
                    peer->last_tx    = now;
                    keypair->last_tx = now;
                }

                pbuf_free(pbuf);

                // Check to see if we should rekey
                if (keypair->sending_counter >= REKEY_AFTER_MESSAGES)
                {
                    peer->send_handshake = true;
                }
                else if (keypair->initiator && wireguard_expired(keypair->keypair_millis, REKEY_AFTER_TIME))
                {
                    peer->send_handshake = true;
                }
            }
            else
            {
                // Failed to allocate memory
                result = ERR_MEM;
            }
        }
        else
        {
            // key has expired...
            keypair_destroy(keypair);
            result = ERR_CONN;
        }
    }
    else
    {
        // No valid keys!
        result = ERR_CONN;
    }
    return result;
}

// This is used as the output function for the Wireguard netif
// The ipaddr here is the one inside the VPN which we use to lookup the correct peer/endpoint
static err_t wireguardifOutput(netif_t *netif, pbuf_t *q, const ip4_addr_t *ipaddr)
{
    wireguard_device_t *device = (wireguard_device_t *) netif->state;
    // Send to peer that matches dest IP
    wireguard_peer_t *peer = peerLookupByAllowedIp(device, ipaddr);
    if (peer)
    {
        return wireguardifOutputToPeer(netif, q, ipaddr, peer);
    }
    else
    {
        return ERR_RTE;
    }
}

static void wireguardifSendKeepalive(wireguard_device_t *device, wireguard_peer_t *peer)
{
    // Send a NULL packet as a keep-alive
    wireguardifOutputToPeer(device->netif, NULL, NULL, peer);
}

static void wireguardifProcessResponseMessage(wireguard_device_t *device, wireguard_peer_t *peer,
                                                 message_handshake_response_t *response, const ip_addr_t *addr,
                                                 u16_t port)
{
    if (wireguard_process_handshake_response(device, peer, response))
    {
        // Packet is good
        // Update the peer location
        updatePeerAddr(peer, addr, port);

        wireguard_start_session(peer, true);
        wireguardifSendKeepalive(device, peer);

        // Set the IF-UP flag on netif
        netif_set_link_up(device->netif);
    }
    else
    {
        // Packet bad
    }
}

static bool peerAddIp(wireguard_peer_t *peer, ip_addr_t ip, ip_addr_t mask)
{
    bool                         result = false;
    wireguard_allowed_ip_t *allowed;
    int                          x;
    // Look for existing match first
    for (x = 0; x < WIREGUARD_MAX_SRC_IPS; x++)
    {
        allowed = &peer->allowed_source_ips[x];
        if ((allowed->valid) && ip_addr_cmp(&allowed->ip, &ip) && ip_addr_cmp(&allowed->mask, &mask))
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

static void wireguardifProcessDataMessage(wireguard_device_t *device, wireguard_peer_t *peer,
                                             message_transport_data_t *data_hdr, size_t data_len,
                                             const ip_addr_t *addr, u16_t port)
{
    wireguard_keypair_t *keypair;
    uint64_t                  nonce;
    uint8_t                  *src;
    size_t                    src_len;
    pbuf_t              *pbuf;
    ip_hdr_t            *iphdr;
    ip_addr_t                 dest;
    bool                      dest_ok = false;
    int                       x;
    uint32_t                  now;
    uint16_t                  header_len = 0xFFFF;
    uint32_t                  idx        = data_hdr->receiver;

    keypair = get_peer_keypair_for_idx(peer, idx);

    if (keypair)
    {
        if ((keypair->receiving_valid) && ! wireguard_expired(keypair->keypair_millis, REJECT_AFTER_TIME) &&
            (keypair->sending_counter < REJECT_AFTER_MESSAGES)

        )
        {

            nonce   = U8TO64_LITTLE(data_hdr->counter);
            src     = &data_hdr->enc_packet[0];
            src_len = data_len;

            // We don't know the unpadded size until we have decrypted the packet and validated/inspected the IP header
            pbuf = pbuf_alloc(PBUF_TRANSPORT, src_len - WIREGUARD_AUTHTAG_LEN, PBUF_RAM);
            if (pbuf)
            {
                // Decrypt the packet
                memset(pbuf->payload, 0, pbuf->tot_len);
                if (wireguard_decrypt_packet(pbuf->payload, src, src_len, nonce, keypair))
                {

                    // 3. Since the packet has authenticated correctly, the source IP of the outer UDP/IP packet is used
                    // to update the endpoint for peer TrMv...WXX0. Update the peer location
                    updatePeerAddr(peer, addr, port);

                    now              = wireguard_sys_now();
                    keypair->last_rx = now;
                    peer->last_rx    = now;

                    // Might need to shuffle next key --> current keypair
                    keypair_update(peer, keypair);

                    // Check to see if we should rekey
                    if (keypair->initiator &&
                        wireguard_expired(keypair->keypair_millis,
                                          REJECT_AFTER_TIME - peer->keepalive_interval - REKEY_TIMEOUT))
                    {
                        peer->send_handshake = true;
                    }

                    // Make sure that link is reported as up
                    netif_set_link_up(device->netif);

                    if (pbuf->tot_len > 0)
                    {
                        // 4a. Once the packet payload is decrypted, the interface has a plaintext packet. If this is
                        // not an IP packet, it is dropped.
                        iphdr = (ip_hdr_t *) pbuf->payload;
                        // Check for packet replay / dupes
                        if (wireguard_check_replay(keypair, nonce))
                        {

                            // 4b. Otherwise, WireGuard checks to see if the source IP address of the plaintext
                            // inner-packet routes correspondingly in the cryptokey routing table Also check packet
                            // length!
#if LWIP_IPV4
                            if (IPH_V(iphdr) == 4)
                            {
                                ip_addr_copy_from_ip4(dest, iphdr->dest);
                                for (x = 0; x < WIREGUARD_MAX_SRC_IPS; x++)
                                {
                                    if (peer->allowed_source_ips[x].valid)
                                    {
                                        if (ip_addr_netcmp(&dest, &peer->allowed_source_ips[x].ip,
                                                           &peer->allowed_source_ips[x].mask))
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
                            if (header_len <= pbuf->tot_len)
                            {

                                // 5. If the plaintext packet has not been dropped, it is inserted into the receive
                                // queue of the wg0 interface.
                                if (dest_ok)
                                {
                                    // Send packet to be process by LWIP
                                    ip_input(pbuf, device->netif);
                                    // pbuf is owned by IP layer now
                                    pbuf = NULL;
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
                    }
                }

                if (pbuf)
                {
                    pbuf_free(pbuf);
                }
            }
        }
        else
        {
            // After Reject-After-Messages transport data messages or after the current secure session is Reject-
            // After-Time seconds old,
            //  whichever comes first, WireGuard will refuse to send or receive any more transport data messages using
            //  the current secure session, until a new secure session is created through the 1-RTT handshake
            keypair_destroy(keypair);
        }
    }
    else
    {
        // Could not locate valid keypair for remote index
    }
}

static pbuf_t *wireguardifInitiateHandshake(wireguard_device_t *device, wireguard_peer_t *peer,
                                                   message_handshake_initiation_t *msg, err_t *error)
{
    pbuf_t *pbuf = NULL;
    err_t        err  = ERR_OK;
    if (wireguard_create_handshake_initiation(device, peer, msg))
    {
        // Send this packet out!
        pbuf = pbuf_alloc(PBUF_TRANSPORT, sizeof(message_handshake_initiation_t), PBUF_RAM);
        if (pbuf)
        {
            err = pbuf_take(pbuf, msg, sizeof(message_handshake_initiation_t));
            if (err == ERR_OK)
            {
                // OK!
            }
            else
            {
                pbuf_free(pbuf);
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

static void wireguardifSendHandshakeResponse(wireguard_device_t *device, wireguard_peer_t *peer)
{
    message_handshake_response_t packet;
    pbuf_t                      *pbuf = NULL;
    err_t                             err  = ERR_OK;

    if (wireguard_create_handshake_response(device, peer, &packet))
    {

        wireguard_start_session(peer, false);

        // Send this packet out!
        pbuf = pbuf_alloc(PBUF_TRANSPORT, sizeof(message_handshake_response_t), PBUF_RAM);
        if (pbuf)
        {
            err = pbuf_take(pbuf, &packet, sizeof(message_handshake_response_t));
            if (err == ERR_OK)
            {
                // OK!
                wireguardifPeerOutput(device->netif, pbuf, peer);
            }
            pbuf_free(pbuf);
        }
    }
}

static size_t getSourceAddrPort(const ip_addr_t *addr, u16_t port, uint8_t *buf, size_t buflen)
{
    size_t result = 0;

#if LWIP_IPV4
    if (IP_IS_V4(addr) && (buflen >= 4))
    {
        U32TO8_BIG(buf + result, PP_NTOHL(ip4_addr_get_u32(addr)));
        result += 4;
    }
#endif
#if LWIP_IPV6
    if (IP_IS_V4(addr) && (buflen >= 16))
    {
        U16TO8_BIG(buf + result + 0, IP6_ADDR_BLOCK1(addr));
        U16TO8_BIG(buf + result + 2, IP6_ADDR_BLOCK2(addr));
        U16TO8_BIG(buf + result + 4, IP6_ADDR_BLOCK3(addr));
        U16TO8_BIG(buf + result + 6, IP6_ADDR_BLOCK4(addr));
        U16TO8_BIG(buf + result + 8, IP6_ADDR_BLOCK5(addr));
        U16TO8_BIG(buf + result + 10, IP6_ADDR_BLOCK6(addr));
        U16TO8_BIG(buf + result + 12, IP6_ADDR_BLOCK7(addr));
        U16TO8_BIG(buf + result + 14, IP6_ADDR_BLOCK8(addr));
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
                                              const ip_addr_t *addr, u16_t port)
{
    message_cookie_reply_t packet;
    pbuf_t                *pbuf = NULL;
    err_t                       err  = ERR_OK;
    uint8_t                     source_buf[18];
    size_t                      source_len = getSourceAddrPort(addr, port, source_buf, sizeof(source_buf));

    wireguard_create_cookie_reply(device, &packet, mac1, index, source_buf, source_len);

    // Send this packet out!
    pbuf = pbuf_alloc(PBUF_TRANSPORT, sizeof(message_cookie_reply_t), PBUF_RAM);
    if (pbuf)
    {
        err = pbuf_take(pbuf, &packet, sizeof(message_cookie_reply_t));
        if (err == ERR_OK)
        {
            wireguardifDeviceOutput(device, pbuf, addr, port);
        }
        pbuf_free(pbuf);
    }
}

static bool wireguardifCheckInitiationMessage(wireguard_device_t             *device,
                                                 message_handshake_initiation_t *msg, const ip_addr_t *addr,
                                                 u16_t port)
{
    bool     result = false;
    uint8_t *data   = (uint8_t *) msg;
    uint8_t  source_buf[18];
    size_t   source_len;
    // We received an initiation packet check it is valid

    if (wireguard_check_mac1(device, data, sizeof(message_handshake_initiation_t) - (2 * WIREGUARD_COOKIE_LEN),
                             msg->mac1))
    {
        // mac1 is valid!
        if (! wireguard_is_under_load())
        {
            // If we aren't under load we only need mac1 to be correct
            result = true;
        }
        else
        {
            // If we are under load then check mac2
            source_len = getSourceAddrPort(addr, port, source_buf, sizeof(source_buf));

            result =
                wireguard_check_mac2(device, data, sizeof(message_handshake_initiation_t) - (WIREGUARD_COOKIE_LEN),
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

static bool wireguardifCheckResponseMessage(wireguard_device_t *device, message_handshake_response_t *msg,
                                               const ip_addr_t *addr, u16_t port)
{
    bool     result = false;
    uint8_t *data   = (uint8_t *) msg;
    uint8_t  source_buf[18];
    size_t   source_len;
    // We received an initiation packet check it is valid

    if (wireguard_check_mac1(device, data, sizeof(message_handshake_response_t) - (2 * WIREGUARD_COOKIE_LEN),
                             msg->mac1))
    {
        // mac1 is valid!
        if (! wireguard_is_under_load())
        {
            // If we aren't under load we only need mac1 to be correct
            result = true;
        }
        else
        {
            // If we are under load then check mac2
            source_len = getSourceAddrPort(addr, port, source_buf, sizeof(source_buf));

            result =
                wireguard_check_mac2(device, data, sizeof(message_handshake_response_t) - (WIREGUARD_COOKIE_LEN),
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

void wireguardifNetworkRx(void *arg, udp_pcb_t *pcb, pbuf_t *p, const ip_addr_t *addr, u16_t port)
{
    LWIP_ASSERT("wireguardifNetworkRx: invalid arg", arg != NULL);
    LWIP_ASSERT("wireguardifNetworkRx: invalid pbuf", p != NULL);
    // We have received a packet from the base_netif to our UDP port - process this as a possible Wireguard packet
    wireguard_device_t *device = (wireguard_device_t *) arg;
    wireguard_peer_t   *peer;
    uint8_t                 *data = p->payload;
    size_t                   len  = p->len; // This buf, not chained ones

    message_handshake_initiation_t *msg_initiation;
    message_handshake_response_t   *msg_response;
    message_cookie_reply_t         *msg_cookie;
    message_transport_data_t       *msg_data;

    uint8_t type = wireguard_get_message_type(data, len);

    switch (type)
    {
    case MESSAGE_HANDSHAKE_INITIATION:
        msg_initiation = (message_handshake_initiation_t *) data;

        // Check mac1 (and optionally mac2) are correct - note it may internally generate a cookie reply packet
        if (wireguardifCheckInitiationMessage(device, msg_initiation, addr, port))
        {

            peer = wireguard_process_initiation_message(device, msg_initiation);
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
            if (wireguard_process_cookie_message(device, peer, msg_cookie))
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
    pbuf_free(p);
}

static err_t wireguardStartHandshake(netif_t *netif, wireguard_peer_t *peer)
{
    wireguard_device_t            *device = (wireguard_device_t *) netif->state;
    err_t                               result;
    pbuf_t                        *pbuf;
    message_handshake_initiation_t msg;

    pbuf = wireguardifInitiateHandshake(device, peer, &msg, &result);
    if (pbuf)
    {
        result = wireguardifPeerOutput(netif, pbuf, peer);
        pbuf_free(pbuf);
        peer->send_handshake     = false;
        peer->last_initiation_tx = wireguard_sys_now();
        memcpy(peer->handshake_mac1, msg.mac1, WIREGUARD_COOKIE_LEN);
        peer->handshake_mac1_valid = true;
    }
    return result;
}

static err_t wireguardifLookupPeer(netif_t *netif, u8_t peer_index, wireguard_peer_t **out)
{
    LWIP_ASSERT("netif != NULL", (netif != NULL));
    LWIP_ASSERT("state != NULL", (netif->state != NULL));
    wireguard_device_t *device = (wireguard_device_t *) netif->state;
    wireguard_peer_t   *peer   = NULL;
    err_t                    result;

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

err_t wireguardifConnect(netif_t *netif, u8_t peer_index)
{
    wireguard_peer_t *peer;
    err_t                  result = wireguardifLookupPeer(netif, peer_index, &peer);
    if (result == ERR_OK)
    {
        // Check that a valid connect ip and port have been set
        if (! ip_addr_isany(&peer->connect_ip) && (peer->connect_port > 0))
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

err_t wireguardifDisconnect(netif_t *netif, u8_t peer_index)
{
    wireguard_peer_t *peer;
    err_t                  result = wireguardifLookupPeer(netif, peer_index, &peer);
    if (result == ERR_OK)
    {
        // Set the flag that we want to try connecting
        peer->active = false;
        // Wipe out current keys
        keypair_destroy(&peer->next_keypair);
        keypair_destroy(&peer->curr_keypair);
        keypair_destroy(&peer->prev_keypair);
        result = ERR_OK;
    }
    return result;
}

err_t wireguardifPeerIsUp(netif_t *netif, u8_t peer_index, ip_addr_t *current_ip, u16_t *current_port)
{
    wireguard_peer_t *peer;
    err_t                  result = wireguardifLookupPeer(netif, peer_index, &peer);
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

err_t wireguardifRemovePeer(netif_t *netif, u8_t peer_index)
{
    wireguard_peer_t *peer;
    err_t                  result = wireguardifLookupPeer(netif, peer_index, &peer);
    if (result == ERR_OK)
    {
        crypto_zero(peer, sizeof(wireguard_peer_t));
        peer->valid = false;
        result      = ERR_OK;
    }
    return result;
}

err_t wireguardifUpdateEndpoint(netif_t *netif, u8_t peer_index, const ip_addr_t *ip, u16_t port)
{
    wireguard_peer_t *peer;
    err_t                  result = wireguardifLookupPeer(netif, peer_index, &peer);
    if (result == ERR_OK)
    {
        peer->connect_ip   = *ip;
        peer->connect_port = port;
        result             = ERR_OK;
    }
    return result;
}

err_t wireguardifAddPeer(netif_t *netif, wireguardif_peer_t *p, u8_t *peer_index)
{
    LWIP_ASSERT("netif != NULL", (netif != NULL));
    LWIP_ASSERT("state != NULL", (netif->state != NULL));
    LWIP_ASSERT("p != NULL", (p != NULL));
    wireguard_device_t *device = (wireguard_device_t *) netif->state;
    err_t                    result;
    uint8_t                  public_key[WIREGUARD_PUBLIC_KEY_LEN];
    size_t                   public_key_len = sizeof(public_key);
    wireguard_peer_t   *peer           = NULL;

    uint32_t t1 = wireguard_sys_now();

    if (wireguard_base64_decode(p->public_key, public_key, &public_key_len) &&
        (public_key_len == WIREGUARD_PUBLIC_KEY_LEN))
    {

        // See if the peer is already registered
        peer = peerLookupByPubkey(device, public_key);
        if (! peer)
        {
            // Not active - see if we have room to allocate a new one
            peer = peerAlloc(device);
            if (peer)
            {

                if (wireguard_peer_init(device, peer, public_key, p->preshared_key))
                {

                    peer->connect_ip   = p->endpoint_ip;
                    peer->connect_port = p->endport_port;
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
    }
    else
    {
        result = ERR_ARG;
    }

    uint32_t t2 = wireguard_sys_now();
    printf("Adding peer took %ldms\r\n", (t2 - t1));

    if (peer_index)
    {
        if (peer)
        {
            *peer_index = wireguard_peer_index(device, peer);
        }
        else
        {
            *peer_index = WIREGUARDIF_INVALID_INDEX;
        }
    }
    return result;
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
                 wireguard_expired(peer->curr_keypair.keypair_millis, REJECT_AFTER_TIME - peer->keepalive_interval))
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
            if (wireguard_expired(peer->last_tx, peer->keepalive_interval))
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
    if (peer->curr_keypair.valid && (wireguard_expired(peer->curr_keypair.keypair_millis, REJECT_AFTER_TIME) ||
                                     (peer->curr_keypair.sending_counter >= REJECT_AFTER_MESSAGES)))
    {
        result = true;
    }
    return result;
}

static bool shouldResetPeer(wireguard_peer_t *peer)
{
    bool result = false;
    if (peer->curr_keypair.valid && (wireguard_expired(peer->curr_keypair.keypair_millis, REJECT_AFTER_TIME * 3)))
    {
        result = true;
    }
    return result;
}

static void wireguardifTmr(void *arg)
{
    wireguard_device_t *device = (wireguard_device_t *) arg;
    wireguard_peer_t   *peer;
    int                      x;
    // Reschedule this timer
    sys_timeout(WIREGUARDIF_TIMER_MSECS, wireguardifTmr, device);

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
                keypair_destroy(&peer->next_keypair);
                keypair_destroy(&peer->curr_keypair);
                keypair_destroy(&peer->prev_keypair);
                // TODO: Also destroy handshake?

                // Revert back to default IP/port if these were altered
                peer->ip   = peer->connect_ip;
                peer->port = peer->connect_port;
            }
            if (shouldDestroyCurrentKeypair(peer))
            {
                // Destroy current keypair
                keypair_destroy(&peer->curr_keypair);
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
        netif_set_link_down(device->netif);
    }
}

err_t wireguardifInit(netif_t *netif)
{
    err_t                    result;
    wireguardif_init_data_t *init_data;
    wireguard_device_t      *device;
    udp_pcb_t               *udp;
    uint8_t                       private_key[WIREGUARD_PRIVATE_KEY_LEN];
    size_t                        private_key_len = sizeof(private_key);

    LWIP_ASSERT("netif != NULL", (netif != NULL));
    LWIP_ASSERT("state != NULL", (netif->state != NULL));

    // We need to initialise the wireguard module
    wireguard_init();

    if (netif && netif->state)
    {

        // The init data is passed into the netif_add call as the 'state' - we will replace this with our private state
        // data
        init_data = (wireguardif_init_data_t *) netif->state;

        // Clear out and set if function is successful
        netif->state = NULL;

        if (wireguard_base64_decode(init_data->private_key, private_key, &private_key_len) &&
            (private_key_len == WIREGUARD_PRIVATE_KEY_LEN))
        {

            udp = udp_new();

            if (udp)
            {
                result = udp_bind(
                    udp, IP_ADDR_ANY,
                    init_data->listen_port); // Note this listens on all interfaces! Really just want the passed netif
                if (result == ERR_OK)
                {
                    device = (wireguard_device_t *) mem_calloc(1, sizeof(wireguard_device_t));
                    if (device)
                    {
                        device->netif = netif;
                        if (init_data->bind_netif)
                        {
                            udp_bind_netif(udp, init_data->bind_netif);
                        }
                        device->udp_pcb = udp;
                        // Per-wireguard netif/device setup
                        uint32_t t1 = wireguard_sys_now();
                        if (wireguard_device_init(device, private_key))
                        {
                            uint32_t t2 = wireguard_sys_now();
                            printf("Device init took %ldms\r\n", (t2 - t1));

#if LWIP_CHECKSUM_CTRL_PER_NETIF
                            NETIF_SET_CHECKSUM_CTRL(netif, NETIF_CHECKSUM_ENABLE_ALL);
#endif
                            netif->state      = device;
                            netif->name[0]    = 'w';
                            netif->name[1]    = 'g';
                            netif->output     = wireguardifOutput;
                            netif->linkoutput = NULL;
                            netif->hwaddr_len = 0;
                            netif->mtu        = WIREGUARDIF_MTU;
                            // We set up no state flags here - caller should set them
                            // NETIF_FLAG_LINK_UP is automatically set/cleared when at least one peer is connected
                            netif->flags = 0;

                            udp_recv(udp, wireguardifNetworkRx, device);

                            // Start a periodic timer for this wireguard device
                            sys_timeout(WIREGUARDIF_TIMER_MSECS, wireguardifTmr, device);

                            result = ERR_OK;
                        }
                        else
                        {
                            mem_free(device);
                            device = NULL;
                            udp_remove(udp);
                            result = ERR_ARG;
                        }
                    }
                    else
                    {
                        udp_remove(udp);
                        result = ERR_MEM;
                    }
                }
                else
                {
                    udp_remove(udp);
                }
            }
            else
            {
                result = ERR_MEM;
            }
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
    return result;
}

void wireguardifPeerInit(wireguardif_peer_t *peer)
{
    LWIP_ASSERT("peer != NULL", (peer != NULL));
    memset(peer, 0, sizeof(wireguardif_peer_t));
    // Caller must provide 'public_key'
    peer->public_key = NULL;
    ip4_addr_set_any(&peer->endpoint_ip);
    peer->endport_port = WIREGUARDIF_DEFAULT_PORT;
    peer->keep_alive   = WIREGUARDIF_KEEPALIVE_DEFAULT;
    ip4_addr_set_any(&peer->allowed_ip);
    ip4_addr_set_any(&peer->allowed_mask);
    memset(peer->greatest_timestamp, 0, sizeof(peer->greatest_timestamp));
    peer->preshared_key = NULL;
}
