#include "structure.h"

void domainresolverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase != kDomainResolverPhaseOpen)
    {
        return;
    }

    tunnelPrevDownStreamEst(t, l);
}
