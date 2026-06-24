#include "structure.h"

void domainresolverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);

    domainresolverLinestateInitialize(ls);

    bool resolving = false;
    if (UNLIKELY(! domainresolverStartResolveIfNeeded(t, l, ls, kDomainResolverDirectionUpstream, &resolving)))
    {
        domainresolverCloseBeforeInit(t, l, kDomainResolverDirectionUpstream);
        return;
    }

    if (resolving)
    {
        return;
    }

    tunnelNextUpStreamInit(t, l);
}
