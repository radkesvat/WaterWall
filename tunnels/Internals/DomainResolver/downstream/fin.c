#include "structure.h"

void domainresolverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);
    if (ls->dns_transport != NULL)
    {
        domainresolverTransportFinish(t, l);
        return;
    }
    bool source_finished = ls->phase == kDomainResolverPhaseClosing;
    domainresolverLinestateDestroy(t, l, ls);
    if (! source_finished)
        tunnelPrevDownStreamFinish(t, l);
}
