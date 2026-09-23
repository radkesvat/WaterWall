#include "structure.h"

void domainresolverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls       = lineGetState(l, t);
    bool                     was_open = ls->phase == kDomainResolverPhaseOpen;
    domainresolverLinestateDestroy(t, l, ls);
    if (was_open)
        tunnelNextUpStreamFinish(t, l);
}
