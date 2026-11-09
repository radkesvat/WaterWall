#include "structure.h"

void domainresolverTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);

    // Chain-mode query lines enter at the injection point after this resolver, never here.
    assert(ls->chain_query == NULL);
    domainresolverLinestateInitialize(t, ls);

    domainresolver_tstate_t *ts = tunnelGetState(t);
    if (ts->prepare != NULL && UNLIKELY(! ts->prepare(t, ts->prepare_owner, l, domainresolverGetUserLineState(ts, ls))))
    {
        domainresolverCloseLine(t, l);
        return;
    }

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
