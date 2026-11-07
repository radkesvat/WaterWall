#include "structure.h"

#include "loggers/network_logger.h"

void reverseserverLinestateInitialize(reverseserver_lstate_t *ls, line_t *u, line_t *d)
{

    *ls = (reverseserver_lstate_t) {
        .next       = NULL,
        .u          = u,
        .d          = d,
        .paired     = false,
        .handshaked = false,
    };
    bufferbudgetInit(&ls->pending_budget,
                     (buffer_budget_cost_t) {.bytes = kReverseServerPendingBytes, .charge = 8U * 1024U * 1024U});
    bufferqueueInitEmpty(&ls->pending);
    bufferqueueAttachBudget(&ls->pending, &ls->pending_budget);
}

void reverseserverLinestateDestroy(reverseserver_lstate_t *ls)
{
    bufferqueueDestroy(&ls->pending);
    bufferbudgetAssertEmpty(&ls->pending_budget);

    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(reverseserver_lstate_t)));
}
