#include "context_queue.h"
#include "buffer_pool.h"
#include "stc/common.h"
#include "tunnel.h"

#define i_TYPE queue, context_t * // NOLINT
#include "stc/deq.h"

enum
{
    kQCap = 16
};

struct context_queue_s
{
    queue          q;
};

context_queue_t *contextqueueCreate(void)
{
    context_queue_t *cb = memoryAllocate(sizeof(context_queue_t));
    cb->q               = queue_with_capacity(kQCap);
    return cb;
}

void contextqueueDestory(context_queue_t *self)
{
    c_foreach(i, queue, self->q)
    {
        if ((*i.ref)->payload != NULL)
        {
            reuseContextPayload(*i.ref);
        }
        destroyContext((*i.ref));
    }

    queue_drop(&self->q);
    memoryFree(self);
}

void contextqueuePush(context_queue_t *self, context_t *context)
{
    queue_push_back(&self->q, context);
}

context_t *contextqueuePop(context_queue_t *self)
{
    context_t *context = queue_pull_front(&self->q);
    return context;
}

size_t contextqueueLen(context_queue_t *self)
{
    return queue_size(&self->q);
}
