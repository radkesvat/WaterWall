#include "structure.h"

void domainresolverTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kDomainResolverPhaseResolving)
    {
        discard domainresolverQueueResolvingPayload(t, l, ls, buf, kDomainResolverDirectionDownstream);
        return;
    }

    if (ls->phase != kDomainResolverPhaseOpen)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}
