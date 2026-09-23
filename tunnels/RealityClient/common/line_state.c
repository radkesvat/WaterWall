#include "structure.h"

void realityclientLinestateInitialize(realityclient_lstate_t *ls, buffer_pool_t *pool)
{
    *ls = (realityclient_lstate_t) {
        .read_stream    = bufferstreamCreate(pool, kRealityClientMaxFramePrefixSize),
        .handoff_stream = bufferstreamCreate(pool, 0),
        .pending_up     = bufferqueueCreate(2),
        .phase          = kRealityClientPhaseTlsHandshake,
    };
    bufferbudgetInit(&ls->pending_budget,
                     (buffer_budget_cost_t) {kRealityClientPendingBytes, SIZE_MAX, kRealityClientPendingBuffers});
    const bool attached = bufferqueueTryAttachBudget(&ls->pending_up, &ls->pending_budget);
    assert(attached);
    discard attached;
}

void realityclientLinestateDestroy(realityclient_lstate_t *ls)
{
    if (ls->pending_active != NULL)
    {
        bufferpoolReuseBuffer(ls->read_stream.pool, ls->pending_active);
    }
    bufferstreamDestroy(&ls->read_stream);
    bufferstreamDestroy(&ls->handoff_stream);
    bufferqueueDestroy(&ls->pending_up);
    bufferbudgetReservationRelease(&ls->pending_reservation);
    bufferbudgetAssertEmpty(&ls->pending_budget);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(*ls)));
}
