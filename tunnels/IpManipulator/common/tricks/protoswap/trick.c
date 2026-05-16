#include "trick.h"

#include "loggers/network_logger.h"

static bool protoswapIsTcpUdp(uint8_t protocol)
{
    return protocol == IPPROTO_TCP || protocol == IPPROTO_UDP;
}

static void protoswapRefreshIpv4HeaderChecksum(struct ip_hdr *ipheader)
{
    uint16_t ip_header_len = IPH_HL_BYTES(ipheader);
    uint16_t ip_total_len  = lwip_ntohs(IPH_LEN(ipheader));

    if (ip_header_len < IP_HLEN || ip_header_len > IP_HLEN_MAX || ip_total_len < ip_header_len)
    {
        return;
    }

    IPH_CHKSUM_SET(ipheader, 0);
    IPH_CHKSUM_SET(ipheader, inet_chksum(ipheader, ip_header_len));
}

static void protoswapSetProtocol(line_t *l, struct ip_hdr *ipheader, uint8_t original_protocol, uint8_t new_protocol)
{
    if (new_protocol == original_protocol)
    {
        return;
    }

    IPH_PROTO_SET(ipheader, new_protocol);

    if (protoswapIsTcpUdp(original_protocol) && protoswapIsTcpUdp(new_protocol))
    {
        protoswapRefreshIpv4HeaderChecksum(ipheader);
        return;
    }

    lineSetRecalculateChecksum(l, true);
}

static void protoswapApply(tunnel_t *t, line_t *l, sbuf_t *buf, bool upstream)
{
    ipmanipulator_tstate_t *state    = tunnelGetState(t);
    struct ip_hdr          *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);

    if (IPH_V(ipheader) != 4)
    {
        return;
    }

    uint8_t original_protocol = IPH_PROTO(ipheader);
    int     new_protocol      = -1;

    if (state->trick_proto_swap_tcp_number != -1)
    {
        if (original_protocol == IPPROTO_TCP)
        {
            if (state->trick_proto_swap_tcp_number_2 != -1)
            {
                int *toggle =
                    upstream ? &state->trick_proto_swap_tcp_toggle_up : &state->trick_proto_swap_tcp_toggle_down;
                new_protocol =
                    (*toggle == 0) ? state->trick_proto_swap_tcp_number : state->trick_proto_swap_tcp_number_2;
                *toggle = (*toggle == 0) ? 1 : 0;
            }
            else
            {
                new_protocol = state->trick_proto_swap_tcp_number;
            }
        }
        else if (original_protocol == state->trick_proto_swap_tcp_number ||
                 original_protocol == state->trick_proto_swap_tcp_number_2)
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

    if (new_protocol != -1)
    {
        protoswapSetProtocol(l, ipheader, original_protocol, (uint8_t) new_protocol);
    }
}

void protoswaptrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    protoswapApply(t, l, buf, true);
}

void protoswaptrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    protoswapApply(t, l, buf, false);
}
