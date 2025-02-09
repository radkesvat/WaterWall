#include "context_queue.h"
#include "buffer_pool.h"
#include "stc/common.h"
#include "tunnel.h"

#define i_type queue_t
#define i_key context_t *
#include "stc/deque.h"

enum
{
    kQCap = 8
};

struct context_queue_s
{
    queue_t          q;
};

/*
    Creates a new context queue.
    @return A pointer to the newly created context queue, or NULL on failure.
*/
context_queue_t *contextqueueCreate(void)
{
    context_queue_t *cb = memoryAllocate(sizeof(context_queue_t));
    cb->q               = queue_t_with_capacity(kQCap);
    return cb;
}

/*
    Destroys a context queue, freeing all its resources.
    @param self A pointer to the context queue to destroy.
*/
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

/*
    Pushes a context onto the back of the queue.
    @param self A pointer to the context queue.
    @param context A pointer to the context to push onto the queue.
*/
void contextqueuePush(context_queue_t *self, context_t *context)
{
    queue_t_push_back(&self->q, context);
}

/*
    Pops a context from the front of the queue.
    @param self A pointer to the context queue.
    @return A pointer to the context that was popped from the queue, or NULL if the queue is empty.
*/
context_t *contextqueuePop(context_queue_t *self)
{
    context_t *context = queue_t_pull_front(&self->q);
    return context;
}

/*
    Gets the number of contexts in the queue.
    @param self A pointer to the context queue.
    @return The number of contexts in the queue.
*/
size_t contextqueueLen(context_queue_t *self)
{
    return queue_t_size(&self->q);
}
