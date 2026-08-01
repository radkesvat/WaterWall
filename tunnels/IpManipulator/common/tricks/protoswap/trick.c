#include "trick.h"

#include "loggers/network_logger.h"

static bool protoswapSetProtocol(sbuf_t *buf, uint8_t new_protocol)
{
    if (UNLIKELY(sbufGetLength(buf) < sizeof(struct ip_hdr)))
    {
        return false;
    }

    const struct ip_hdr *ipheader = (const struct ip_hdr *) sbufGetRawPtr(buf);

    if (IPH_V(ipheader) != 4)
    {
        return false;
    }

    uint16_t ip_hdr_len = IPH_HL_BYTES(ipheader);
    if (ip_hdr_len < IP_HLEN || ip_hdr_len > IP_HLEN_MAX || ip_hdr_len > sbufGetLength(buf))
    {
        return false;
    }

    uint16_t ip_total_len = lwip_ntohs(IPH_LEN(ipheader));
    if (ip_total_len < ip_hdr_len || ip_total_len > sbufGetLength(buf))
    {
        return false;
    }

    if (IPH_PROTO(ipheader) == new_protocol)
    {
        return true;
    }

    uint8_t        old_proto    = IPH_PROTO(ipheader);
    uint16_t       old_chksum   = IPH_CHKSUM(ipheader);
    struct ip_hdr *mut_ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);

    IPH_PROTO_SET(mut_ipheader, new_protocol);

    if (calcIpv4HeaderChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf)))
    {
        return true;
    }

    IPH_PROTO_SET(mut_ipheader, old_proto);
    IPH_CHKSUM_SET(mut_ipheader, old_chksum);
    return false;
}

static void protoswapApply(tunnel_t *t, line_t *l, sbuf_t *buf, bool upstream)
{
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    if (UNLIKELY(sbufGetLength(buf) < sizeof(struct ip_hdr)))
    {
        return;
    }

    const struct ip_hdr *ipheader = (const struct ip_hdr *) sbufGetRawPtr(buf);

    if (IPH_V(ipheader) != 4)
    {
        return;
    }

    uint16_t ip_hdr_len = IPH_HL_BYTES(ipheader);
    if (ip_hdr_len < IP_HLEN || ip_hdr_len > IP_HLEN_MAX || ip_hdr_len > sbufGetLength(buf))
    {
        return;
    }

    uint16_t ip_total_len = lwip_ntohs(IPH_LEN(ipheader));
    if (ip_total_len < ip_hdr_len || ip_total_len > sbufGetLength(buf))
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
                atomic_uint *toggle_ptr =
                    upstream ? &state->trick_proto_swap_tcp_toggle_up : &state->trick_proto_swap_tcp_toggle_down;
                unsigned int counter = (unsigned int) atomicIncRelaxed(toggle_ptr);
                new_protocol =
                    (counter % 2U == 0) ? state->trick_proto_swap_tcp_number : state->trick_proto_swap_tcp_number_2;
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
        protoswapSetProtocol(buf, (uint8_t) new_protocol);
    }

    discard l;
}

void protoswaptrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    protoswapApply(t, l, buf, true);
}

void protoswaptrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    protoswapApply(t, l, buf, false);
}
