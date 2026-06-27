#include "structure.h"

void domainresolverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);

    domainresolverLinestateInitialize(t, ls);

    domainresolver_tstate_t *ts = tunnelGetState(t);
    if (ts->prepare != NULL &&
        UNLIKELY(! ts->prepare(t,
                               ts->prepare_owner,
                               l,
                               kDomainResolverDirectionDownstream,
                               domainresolverGetUserLineState(ts, ls))))
    {
        domainresolverCloseBeforeInit(t, l, kDomainResolverDirectionDownstream);
        return;
    }

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
