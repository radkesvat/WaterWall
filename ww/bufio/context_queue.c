#include "context_queue.h"
#include "buffer_pool.h"
#include "stc/common.h"
#include "tunnel.h"

#define i_type queue_t
#define i_key context_t *
#include "stc/deq.h"

enum
{
    kQCap = 16
};

struct context_queue_s
{
    queue_t          q;
};

context_queue_t *contextqueueCreate(void)
{
    context_queue_t *cb = memoryAllocate(sizeof(context_queue_t));
    cb->q               = queue_t_with_capacity(kQCap);
    return cb;
}

void contextqueueDestory(context_queue_t *self)
{
    c_foreach(i, queue_t, self->q)
    {
        if ((*i.ref)->payload != NULL)
        {
            contextReusePayload(*i.ref);
        }
        contextDestroy((*i.ref));
    }

    queue_t_drop(&self->q);
    memoryFree(self);
}

void contextqueuePush(context_queue_t *self, context_t *context)
{
    queue_t_push_back(&self->q, context);
}

context_t *contextqueuePop(context_queue_t *self)
{
    context_t *context = queue_t_pull_front(&self->q);
    return context;
}

size_t contextqueueLen(context_queue_t *self)
{
    return queue_t_size(&self->q);
}
