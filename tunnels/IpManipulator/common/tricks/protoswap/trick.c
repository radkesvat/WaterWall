#include "trick.h"

#include "loggers/network_logger.h"

void protoswaptrickUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t *state    = tunnelGetState(t);
    struct ip_hdr          *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);

    if (IPH_V(ipheader) == 4)
    {
        if (state->trick_proto_swap_tcp_number != -1)
        {
            if (IPH_PROTO(ipheader) == IPPROTO_TCP)
            {
                IPH_PROTO_SET(ipheader, state->trick_proto_swap_tcp_number);
                l->recalculate_checksum = true;
            }
            else if (IPH_PROTO(ipheader) == state->trick_proto_swap_tcp_number)
            {
                IPH_PROTO_SET(ipheader, IPPROTO_TCP);
                l->recalculate_checksum = true;
            }
        }

        if (state->trick_proto_swap_udp_number != -1)
        {
            if (IPH_PROTO(ipheader) == IPPROTO_UDP)
            {
                IPH_PROTO_SET(ipheader, state->trick_proto_swap_udp_number);
                l->recalculate_checksum = true;
            }
            else if (IPH_PROTO(ipheader) == state->trick_proto_swap_udp_number)
            {
                IPH_PROTO_SET(ipheader, IPPROTO_UDP);
                l->recalculate_checksum = true;
            }
        }
    }

    tunnelNextUpStreamPayload(t, l, buf);
}

void protoswaptrickDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t *state    = tunnelGetState(t);
    struct ip_hdr          *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);

    if (IPH_V(ipheader) == 4)
    {
        if (state->trick_proto_swap_tcp_number != -1)
        {
            if (IPH_PROTO(ipheader) == IPPROTO_TCP)
            {
                IPH_PROTO_SET(ipheader, state->trick_proto_swap_tcp_number);
                l->recalculate_checksum = true;
            }
            else if (IPH_PROTO(ipheader) == state->trick_proto_swap_tcp_number)
            {
                IPH_PROTO_SET(ipheader, IPPROTO_TCP);
                l->recalculate_checksum = true;
            }
        }

        if (state->trick_proto_swap_udp_number != -1)
        {
            if (IPH_PROTO(ipheader) == IPPROTO_UDP)
            {
                IPH_PROTO_SET(ipheader, state->trick_proto_swap_udp_number);
                l->recalculate_checksum = true;
            }
            else if (IPH_PROTO(ipheader) == state->trick_proto_swap_udp_number)
            {
                IPH_PROTO_SET(ipheader, IPPROTO_UDP);
                l->recalculate_checksum = true;
            }
        }
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
