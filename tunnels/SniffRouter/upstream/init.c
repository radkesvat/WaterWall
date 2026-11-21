#include "structure.h"

void sniffrouterTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    sniffrouter_lstate_t *ls = lineGetState(l, t);

    sniffrouterLinestateInitialize(ls);
    address_context_t *dest      = lineGetDestinationAddressContext(l);
    const uint8_t      transport = addresscontextSelectTransport(dest, kAddressContextTransportBoth);
    if (transport == 0)
    {
        tunnelLogTransportRefusal(t, dest, kAddressContextTransportBoth);
        sniffrouterLinestateDestroy(l, ls);
        tunnelPrevDownStreamFinish(t, l);
        return;
    }
    addresscontextSetTransportOffer(dest, transport);
    ls->datagram_input = transport == kAddressContextTransportUdp;

    /*
     * Init is intentionally not propagated yet. The selected branch is
     * initialized lazily after the first cleartext bytes are classified.
     */
}
