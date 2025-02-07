#include "structure.h"

#include "loggers/network_logger.h"


static void wireguardifProcessResponseMessage(wireguard_device_t *device, wireguard_peer_t *peer,
                                              message_handshake_response_t *response, const ip_address_t *addr,
                                              uint16_t port)
{
    if (wireguardProcessHandshakeResponse(device, peer, response))
    {
        // Packet is good
        // Update the peer location
        updatePeerAddr(peer, addr, port);

        wireguard_start_session(peer, true);
        wireguardifSendKeepalive(device, peer);

        // Set the IF-UP flag on ts
        netifSetLinkUp(device->ts);
    }
    else
    {
        // Packet bad
    }
}


void wireguardifNetworkRx(void *arg, udp_pcb_t *pcb, sbuf_t *p, const ip_address_t *addr, uint16_t port)
{
    LWIP_ASSERT("wireguardifNetworkRx: invalid arg", arg != NULL);
    LWIP_ASSERT("wireguardifNetworkRx: invalid pbuf", p != NULL);
    // We have received a packet from the base_netif to our UDP port - process this as a possible Wireguard packet
    wireguard_device_t *device = (wireguard_device_t *) arg;
    wireguard_peer_t   *peer;
    uint8_t            *data = p->payload;
    size_t              len  = p->len; // This buf, not chained ones

    message_handshake_initiation_t *msg_initiation;
    message_handshake_response_t   *msg_response;
    message_cookie_reply_t         *msg_cookie;
    message_transport_data_t       *msg_data;

    uint8_t type = wireguardGetMessageType(data, len);

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
    pbufFree(p);
}


void wireguarddeviceTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tunnelPrevDownStreamPayload(t, l, buf);
}
