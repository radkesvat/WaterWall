#include "structure.h"

void domainresolverLinestateInitialize(domainresolver_lstate_t *ls)
{
    *ls = (domainresolver_lstate_t) {
        .pending       = bufferqueueCreate(kDomainResolverPendingQueueInitialCapacity),
        .phase         = kDomainResolverPhaseIdle,
        .init_direction = kDomainResolverDirectionNone,
    };
}

void domainresolverLinestateDestroy(domainresolver_lstate_t *ls)
{
    bufferqueueDestroy(&ls->pending);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
