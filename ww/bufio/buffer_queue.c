/**
 * @file buffer_queue.c
 * @brief Implementation of the buffer queue for managing sbuf_t buffers.
 */

#include "buffer_queue.h"
#include "buffer_pool.h"
#include "stc/common.h"
#include "tunnel.h"

enum
{
    kBufferQueueQCap = 8 // Initial capacity of the queue
};

buffer_queue_t bufferqueueCreate(int init_capacity)
{
    if (init_capacity < 1)
    {
        init_capacity = kBufferQueueQCap;
    }

    buffer_queue_t bq = {.q = ww_sbuffer_queue_t_with_capacity(init_capacity), .total_len = 0};
    return bq;
}

void bufferqueueDestroy(buffer_queue_t *self)
{
    /*
     * Only resolve the worker pool when there is something to give back: an
     * empty queue must stay destroyable from anywhere, including teardown paths
     * that no longer hold a worker identity.
     */
    if (ww_sbuffer_queue_t_size(&self->q) > 0)
    {
        // Queued buffers are released on the worker that owns them, so the
        // identity is validated once and reused for every buffer.
        buffer_pool_t *pool = getCurrentEventWorkerBufferPool();
        c_foreach(i, ww_sbuffer_queue_t, self->q)
        {
            bufferpoolReuseBuffer(pool, *i.ref);
        }
    }

    ww_sbuffer_queue_t_drop(&self->q);
}

void bufferqueuePushBack(buffer_queue_t *self, sbuf_t *b)
{
    BUFFER_WONT_BE_REUSED(b);
    ww_sbuffer_queue_t_push_back(&self->q, b);
    self->total_len += sbufGetLength(b);
}

void bufferqueuePushFront(buffer_queue_t *self, sbuf_t *b)
{
    BUFFER_WONT_BE_REUSED(b);

    ww_sbuffer_queue_t_push_front(&self->q, b);
    self->total_len += sbufGetLength(b);
}

sbuf_t *bufferqueuePopFront(buffer_queue_t *self)
{
    if (UNLIKELY(ww_sbuffer_queue_t_size(&self->q) == 0))
    {
        return NULL;
    }
    sbuf_t *b = ww_sbuffer_queue_t_pull_front(&self->q);
    self->total_len -= sbufGetLength(b);
    return b;
}

const sbuf_t *bufferqueueFront(buffer_queue_t *self)
{
    if (UNLIKELY(ww_sbuffer_queue_t_size(&self->q) == 0))
    {
        return NULL;
    }
    return *ww_sbuffer_queue_t_front(&self->q);
}

size_t bufferqueueGetBufCount(buffer_queue_t *self)
{
    return (size_t) (ww_sbuffer_queue_t_size(&self->q));
}

size_t bufferqueueGetBufLen(buffer_queue_t *self)
{
    return self->total_len;
}
