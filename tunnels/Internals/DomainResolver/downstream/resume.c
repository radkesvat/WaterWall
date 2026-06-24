#include "structure.h"

void domainresolverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase != kDomainResolverPhaseOpen)
    {
        return;
    }

    tunnelPrevDownStreamResume(t, l);
}
