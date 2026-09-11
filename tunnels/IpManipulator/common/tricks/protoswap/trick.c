#include "trick.h"

#include "ipv4_packet_view.h"

bool protoswapApply(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    ipv4_packet_view_t      packet = {0};
    uint8_t                *bytes  = sbufGetMutablePtr(buf);
    const size_t            length = sbufGetLength(buf);
    if (! ipv4packetviewParse(bytes, length, &packet))
    {
        return false;
    }
    struct ip_hdr *ipheader          = (struct ip_hdr *) bytes;
    uint8_t original_protocol = IPH_PROTO(ipheader);
    int     new_protocol      = -1;

    if (state->trick_proto_swap_tcp_number != -1)
    {
        /*
         * One mapping in each direction, so every fragment of one IPv4 datagram
         * receives the same protocol number and restores back to TCP.
         */
        if (original_protocol == IPPROTO_TCP)
        {
            new_protocol = state->trick_proto_swap_tcp_number;
        }
        else if (original_protocol == state->trick_proto_swap_tcp_number)
        {
            new_protocol = IPPROTO_TCP;
        }
    }

    if (new_protocol == -1 && state->trick_proto_swap_udp_number != -1)
    {
        if (original_protocol == IPPROTO_UDP)
        {
            new_protocol = state->trick_proto_swap_udp_number;
        }
        else if (original_protocol == state->trick_proto_swap_udp_number)
        {
            new_protocol = IPPROTO_UDP;
        }
    }

    if (new_protocol == -1)
    {
        return false;
    }

    const bool    encoding        = original_protocol == IPPROTO_TCP || original_protocol == IPPROTO_UDP;
    const uint8_t native_protocol = encoding ? original_protocol : (uint8_t) new_protocol;
    /* Preflight before satisfying a request: a refused transition must change nothing. */
    if (! updateIpv4TransportChecksumAddresses(bytes, length, native_protocol, 0, 0, 0, 0))
    {
        return false;
    }
    if (encoding && lineGetRecalculateChecksum(l))
    {
        if (! calcFullPacketChecksum(bytes, length))
        {
            return false;
        }
        lineSetRecalculateChecksum(l, false);
    }

    /* Preflight proved these operations cannot fail; none changes packet geometry. */
    const bool adjusted = updateIpv4TransportChecksumAddresses(bytes,
                                                               length,
                                                               native_protocol,
                                                               encoding ? packet.source_address : 0,
                                                               encoding ? packet.destination_address : 0,
                                                               encoding ? 0 : packet.source_address,
                                                               encoding ? 0 : packet.destination_address);
    assert(adjusted);
    discard adjusted;
    IPH_PROTO_SET(ipheader, (uint8_t) new_protocol);
    IPH_CHKSUM_SET(ipheader, 0);
    IPH_CHKSUM_SET(ipheader, inet_chksum(ipheader, packet.ip_header_length));
    return true;
}

void protoswaptrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard protoswapApply(t, l, buf);
}

void protoswaptrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard protoswapApply(t, l, buf);
}
