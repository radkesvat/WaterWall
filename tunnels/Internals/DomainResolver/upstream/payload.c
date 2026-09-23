#include "structure.h"

void domainresolverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    domainresolver_lstate_t *ls = lineGetState(l, t);

    if (ls->phase == kDomainResolverPhaseResolving || ls->init_dispatching || ls->draining ||
        bufferqueueGetBufCount(&ls->pending) != 0)
    {
        if (LIKELY(domainresolverQueuePayload(t, l, ls, buf)))
            discard domainresolverDrainPending(t, l);
        return;
    }

    if (ls->phase != kDomainResolverPhaseOpen)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    tunnelNextUpStreamPayload(t, l, buf);
}
