#include "structure.h"

void domainresolverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);

    if (ls->chain_query != NULL)
    {
        // prev never saw this injected DNS query line.
        dnslineclientOnLineEst(ls->chain_query, l);
        return;
    }

    if (ls->phase != kDomainResolverPhaseOpen)
    {
        return;
    }

    tunnelPrevDownStreamEst(t, l);
}
