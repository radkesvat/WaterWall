#pragma once

/*
 * FIFO queue utilities for storing and draining context_t pointers.
 */

#include "context.h"
#include "tunnel.h"
#include "wlibc.h"

#define i_type ww_context_queue_t
#define i_key  context_t *
#include "stc/deque.h"

/*
 * Simple FIFO queue wrapper for batching context events.
 */
typedef struct context_queue_s
{
    ww_context_queue_t q;
} context_queue_t;

struct context_queue_s;

/**
 * @brief Create a new context queue with default capacity.
 *
 * @return context_queue_t Queue value.
 */
context_queue_t contextqueueCreate(void);

/**
 * @brief Destroy a context queue and all queued contexts.
 *
 * @param self Queue to destroy.
 */
void contextqueueDestroy(context_queue_t *self);

/**
 * @brief Push a context to the back of the queue.
 *
 * @param self Target queue.
 * @param context Context to enqueue.
 */
void contextqueuePush(context_queue_t *self, context_t *context);

/**
 * @brief Pop the next context from the front of the queue.
 *
 * @param self Source queue.
 * @return context_t* Dequeued context, or NULL if empty.
 */
context_t *contextqueuePop(context_queue_t *self);

/**
 * @brief Get the number of queued contexts.
 *
 * @param self Queue to inspect.
 * @return size_t Number of queued elements.
 */
size_t contextqueueLen(const context_queue_t *self);
