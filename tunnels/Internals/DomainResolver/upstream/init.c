#include "structure.h"

void domainresolverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);

    domainresolverLinestateInitialize(t, ls);

    domainresolver_tstate_t *ts = tunnelGetState(t);
    if (ts->prepare != NULL &&
        UNLIKELY(! ts->prepare(t,
                               ts->prepare_owner,
                               l,
                               kDomainResolverDirectionUpstream,
                               domainresolverGetUserLineState(ts, ls))))
    {
        domainresolverCloseBeforeInit(t, l, kDomainResolverDirectionUpstream);
        return;
    }

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
