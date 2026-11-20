#include "structure.h"

void domainresolverTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    domainresolver_lstate_t *ls       = lineGetState(l, t);
    bool                     was_open = ls->phase == kDomainResolverPhaseOpen;
    if (ls->phase == kDomainResolverPhaseClosing)
        return;

    lineRef(l);
    if (was_open && ! ls->init_dispatching && ls->drain_on_finish)
    {
        /* A borrowed line cannot carry this backlog past the source Finish.
         * Retire the source before handing off the existing FIFO. */
        ls->phase = kDomainResolverPhaseClosing;
        while (bufferqueueGetEntryCount(&ls->pending) != 0)
        {
            tunnelNextUpStreamPayload(t, l, bufferqueuePopFront(&ls->pending));
            if (! lineIsAlive(l) || ls->phase != kDomainResolverPhaseClosing)
            {
                lineUnref(l);
                return;
            }
        }
    }
    domainresolverLinestateDestroy(t, l, ls);
    if (was_open)
        tunnelNextUpStreamFinish(t, l);
    lineUnref(l);
}
