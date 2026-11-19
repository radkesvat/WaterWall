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

    /* A later tunnel may set a different protocol for its own carrier. */
    address_context_transport_t transport = addresscontextClassifyTransport(lineGetDestinationAddressContext(l));
    if (transport == kAddressContextTransportNone)
        transport = addresscontextClassifyTransport(lineGetSourceAddressContext(l));
    ls->drain_on_finish = (transport == kAddressContextTransportTcp || transport == kAddressContextTransportNone) &&
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
