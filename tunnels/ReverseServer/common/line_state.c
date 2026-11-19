#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverLinestateInitialize(reverseserver_lstate_t *ls, line_t *u, line_t *d)
{
    *ls = (reverseserver_lstate_t) {.u = u, .d = d, .phase = kReverseHalfOpening};
    bufferbudgetInit(&ls->pending_budget,
                     (buffer_budget_cost_t) {.bytes = kReverseServerPendingBytes, .charge = 8U * 1024U * 1024U});
    bufferqueueInitEmpty(&ls->pending);
    bufferqueueAttachBudget(&ls->pending, &ls->pending_budget);
}

void reverseserverLinestateDestroy(reverseserver_lstate_t *ls)
{
    closeDrainEnd(&ls->close_drain);
    if (ls->activation != NULL)
        lineReuseBuffer(ls->d, ls->activation);
    bufferqueueDestroy(&ls->pending);
    bufferbudgetAssertEmpty(&ls->pending_budget);

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(reverseserver_lstate_t)));
}
