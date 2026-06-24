#include "structure.h"

void domainresolverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase != kDomainResolverPhaseOpen)
    {
        return;
    }

    tunnelNextUpStreamEst(t, l);
}
