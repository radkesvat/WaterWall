#include "structure.h"

void domainresolverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kDomainResolverPhaseResolving)
    {
        discard domainresolverQueueResolvingPayload(t, l, ls, buf, kDomainResolverDirectionUpstream);
        return;
    }

    if (ls->phase != kDomainResolverPhaseOpen)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    tunnelNextUpStreamPayload(t, l, buf);
}
