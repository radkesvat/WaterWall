#include "structure.h"

#include "loggers/network_logger.h"

void ipmanipulatorUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    ipmanipulator_tstate_t *state    = tunnelGetState(t);
    struct ip_hdr          *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);

    if (state->manip_swap_tcp != 0 && IPH_V(ipheader) == 4 && IPH_PROTO(ipheader) == IPPROTO_TCP)
    {
        IPH_PROTO_SET(ipheader, state->manip_swap_tcp);
        IPH_CHKSUM_SET(ipheader, 0);
        IPH_CHKSUM_SET(ipheader, inet_chksum(ipheader, IPH_HL_BYTES(ipheader)));
    }
    tunnelNextUpStreamPayload(t, l, buf);
}
