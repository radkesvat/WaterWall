#include "structure.h"

void sniffrouterTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    sniffrouterLinestateInitialize(ls);
    const address_context_t *dest = lineGetDestinationAddressContext(l);
    ls->datagram_input            = dest->proto_udp && ! dest->proto_tcp && ! dest->proto_icmp && ! dest->proto_packet;

    /*
     * Init is intentionally not propagated yet. The selected branch is
     * initialized lazily after the first cleartext bytes are classified.
     */
}
