#include "context_buffer.h"

#define i_TYPE queue, context_t *
#include "stc/queue.h"
#define Q_CAP 25

struct context_buffer_s
{
    queue q;
};

context_buffer_t *newContextBuffer()
{
    context_buffer_t *cb = malloc(sizeof(context_buffer_t));
    cb->q = queue_with_capacity(Q_CAP);
}
void destroyContextBuffer(context_buffer_t *self)
{
    queue_drop(&self->q);
    free(self);
}

void contextBufferPush(context_buffer_t *self, context_t *context)
{
    queue_push(&self->q, context);
}
context_t * contextBufferPop(context_buffer_t *self)
{
    return queue_pull(&self->q);
}
size_t contextBufferLen(context_buffer_t *self)
{
    return queue_size(&self->q);
}
