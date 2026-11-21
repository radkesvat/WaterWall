#include "structure.h"

void domainresolverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);

    domainresolverLinestateInitialize(t, ls);

    domainresolver_tstate_t *ts = tunnelGetState(t);
    if (ts->prepare != NULL && UNLIKELY(! ts->prepare(t, ts->prepare_owner, l, domainresolverGetUserLineState(ts, ls))))
    {
        domainresolverCloseLine(t, l);
        return;
    }

    /* Only an exact stream can drain like a stream. A flexible offer belongs
     * to the next selector, so preserve its deliveries and the offer. */
    ls->drain_on_finish =
        addresscontextGetTransportOffer(lineGetDestinationAddressContext(l)) == kAddressContextTransportTcp &&
        ! tunnelchainIsWorkerPacketLine(tunnelGetChain(t), l);

    bool resolving = false;
    if (UNLIKELY(! domainresolverStartResolveIfNeeded(t, l, ls, &resolving)))
    {
        domainresolverCloseLine(t, l);
        return;
    }

    if (resolving)
    {
        return;
    }

    domainresolverOpenPath(t, l);
}
