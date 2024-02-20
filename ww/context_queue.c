#include "context_queue.h"

#define i_TYPE queue, context_t *
#include "stc/queue.h"
#define Q_CAP 25

struct context_queue_s
{
    queue q;
};

context_queue_t *newContextQueue()
{
    context_queue_t *cb = malloc(sizeof(context_queue_t));
    cb->q = queue_with_capacity(Q_CAP);
}
void destroyContextQueue(context_queue_t *self)
{
    queue_drop(&self->q);
    free(self);
}

void contextQueuePush(context_queue_t *self, context_t *context)
{
    queue_push(&self->q, context);
}
context_t * contextQueuePop(context_queue_t *self)
{
    return queue_pull(&self->q);
}
size_t contextQueueLen(context_queue_t *self)
{
    return queue_size(&self->q);
}
