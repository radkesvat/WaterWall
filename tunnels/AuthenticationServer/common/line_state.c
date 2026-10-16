#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverLinestateInitialize(authenticationserver_lstate_t *ls, buffer_pool_t *pool)
{
    *ls = (authenticationserver_lstate_t) {.read_stream    = bufferstreamCreate(pool, 0),
                                           .response_queue = bufferqueueCreate(kAuthenticationServerResponseQueueCap),
                                           .pool           = pool};
    bufferbudgetInit(&ls->response_budget,
                     (buffer_budget_cost_t) {.bytes   = kAuthenticationServerMaxResponseQueue,
                                             .charge  = kAuthenticationServerMaxResponseCharge,
                                             .entries = kAuthenticationServerMaxResponseEntries});
    const bool attached = bufferqueueTryAttachBudget(&ls->response_queue, &ls->response_budget);
    assert(attached);
    discard attached;
}

void authenticationserverLinestateDestroy(authenticationserver_lstate_t *ls)
{
    bufferstreamDestroy(&ls->read_stream);
    bufferqueueDestroy(&ls->response_queue);
    if (ls->active_response != NULL)
    {
        bufferpoolReuseBuffer(ls->pool, ls->active_response);
    }
    bufferbudgetReservationRelease(&ls->active_response_cost);
    bufferbudgetAssertEmpty(&ls->response_budget);
    memoryZeroAligned32(ls, tunnelGetCorrectAlignedLineStateSize(sizeof(authenticationserver_lstate_t)));
}
