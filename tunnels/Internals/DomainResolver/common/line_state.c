#include "structure.h"

void *domainresolverGetUserLineState(domainresolver_tstate_t *ts, domainresolver_lstate_t *ls)
{
    if (ts->user_lstate_size == 0)
    {
        return NULL;
    }

    return ((uint8_t *) ls) + ts->user_lstate_offset;
}

void domainresolverLinestateInitialize(tunnel_t *t, domainresolver_lstate_t *ls)
{
    domainresolver_tstate_t *ts = tunnelGetState(t);

    *ls = (domainresolver_lstate_t) {
        .pending        = bufferqueueCreate(kDomainResolverPendingQueueInitialCapacity),
        .phase          = kDomainResolverPhaseIdle,
        .init_direction = kDomainResolverDirectionNone,
    };

    if (ts->user_lstate_size > 0)
    {
        memoryZeroAligned32(domainresolverGetUserLineState(ts, ls), ts->user_lstate_size);
    }
}

void domainresolverLinestateDestroy(tunnel_t *t, line_t *l, domainresolver_lstate_t *ls)
{
    domainresolver_tstate_t *ts = tunnelGetState(t);

    if (ts->user_lstate_destroy != NULL && ts->user_lstate_size > 0)
    {
        ts->user_lstate_destroy(t, ts->prepare_owner, l, domainresolverGetUserLineState(ts, ls));
    }

    bufferqueueDestroy(&ls->pending);
    memoryZeroAligned32(ls, t->lstate_size);
}
