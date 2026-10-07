/*
 * Implements FIFO queue operations for context_t pointers.
 */

#include "context_queue.h"
#include "buffer_pool.h"
#include "loggers/internal_logger.h"
#include "stc/common.h"
#include "tunnel.h"

enum
{
    kContextQueueCap = 8
};


context_queue_t contextqueueCreate(void)
{

    context_queue_t cq;
    cq.q = ww_context_queue_t_with_capacity(kContextQueueCap);
    return cq;
}

void contextqueueDestroy(context_queue_t *self)
{
    c_foreach(i, ww_context_queue_t, self->q)
    {
        contextDestroy((*i.ref));
    }

    ww_context_queue_t_drop(&self->q);
}

void contextqueuePush(context_queue_t *self, context_t *context)
{
    if (UNLIKELY(ww_context_queue_t_push_back(&self->q, context) == NULL))
    {
        LOGF("ContextQueue: queue insertion failed");
        abortProgramNow(1);
    }
}

context_t *contextqueuePop(context_queue_t *self)
{
    if (ww_context_queue_t_is_empty(&self->q))
    {
        return NULL;
    }
    context_t *context = ww_context_queue_t_pull_front(&self->q);
    return context;
}

size_t contextqueueLen(context_queue_t *self)
{
    return (size_t) (ww_context_queue_t_size(&self->q));
}
