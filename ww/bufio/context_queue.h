#pragma once

#include "context.h"
#include "tunnel.h"
#include "wlibc.h"

#define i_type ww_context_queue_t
#define i_key  context_t *
#include "stc/deque.h"

/*
    a queue for context type, this helps storing it and
    later using it, its a very simple queue
*/
typedef struct context_queue_s
{
    ww_context_queue_t q;
} context_queue_t;

/*
    Represents a queue of context_t pointers.
*/
struct context_queue_s;

/*
    Creates a new context queue.
    @return A pointer to the newly created context queue, or NULL on failure.
*/
context_queue_t contextqueueCreate(void);

/*
    Destroys a context queue, freeing all its resources.
    @param self A pointer to the context queue to destroy.
*/
void contextqueueDestory(context_queue_t *self);

/*
    Pushes a context onto the back of the queue.
    @param self A pointer to the context queue.
    @param context A pointer to the context to push onto the queue.
*/
void contextqueuePush(context_queue_t *self, context_t *context);

/*
    Pops a context from the front of the queue.
    @param self A pointer to the context queue.
    @return A pointer to the context that was popped from the queue, or NULL if the queue is empty.
*/
context_t *contextqueuePop(context_queue_t *self);

/*
    Gets the number of contexts in the queue.
    @param self A pointer to the context queue.
    @return The number of contexts in the queue.
*/
size_t contextqueueLen(context_queue_t *self);
