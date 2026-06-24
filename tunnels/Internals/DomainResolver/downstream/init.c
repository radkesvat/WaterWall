#include "structure.h"

void domainresolverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);

    domainresolverLinestateInitialize(ls);

    bool resolving = false;
    if (UNLIKELY(! domainresolverStartResolveIfNeeded(t, l, ls, kDomainResolverDirectionDownstream, &resolving)))
    {
        domainresolverCloseBeforeInit(t, l, kDomainResolverDirectionDownstream);
        return;
    }

    if (resolving)
    {
        return;
    }

    tunnelPrevDownStreamInit(t, l);
}
