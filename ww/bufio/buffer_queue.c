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

void bufferqueueInitEmpty(buffer_queue_t *self)
{
    self->q         = ww_sbuffer_queue_t_init();
    self->total_len = 0;
}

/*
 * STC's _with_capacity() is not usable here. It computes the ring size first and
 * only then allocates, so a refused allocation publishes {cbuf == NULL,
 * capmask != 0} - a queue that reports storage it does not have, and whose first
 * insertion writes through NULL. _init() plus a checked _reserve() is the only
 * construction that cannot produce that state.
 */
bool bufferqueueInit(buffer_queue_t *self, int init_capacity)
{
    if (init_capacity < 1)
    {
        init_capacity = kBufferQueueQCap;
    }

    bufferqueueInitEmpty(self);
    return ww_sbuffer_queue_t_reserve(&self->q, init_capacity);
}

buffer_queue_t bufferqueueCreate(int init_capacity)
{
    buffer_queue_t bq;

    // The empty queue left behind by a refused reservation is valid and will
    // allocate again on first use, so this stays best effort by design.
    discard bufferqueueInit(&bq, init_capacity);
    return bq;
}

bool bufferqueueReserveExtra(buffer_queue_t *self, size_t extra)
{
    const size_t size = (size_t) ww_sbuffer_queue_t_size(&self->q);

    if (UNLIKELY(extra > (size_t) PTRDIFF_MAX - size))
    {
        return false;
    }

    return ww_sbuffer_queue_t_reserve(&self->q, (isize_t) (size + extra));
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

/*
 * Reserving one slot first makes the insertion below infallible: STC only grows
 * when the ring is full, and after the reserve it provably is not. A NULL here
 * would mean the container itself is corrupt, not that memory ran out, and by
 * that point the Debug replacement has already destroyed the caller's original -
 * so there is nothing left to hand back and no honest failure to report.
 */
static void bufferqueueInsertReserved(sbuf_t *slot, const char *where)
{
    if (UNLIKELY(slot == NULL))
    {
        printError("buffer queue: %s failed after a successful reservation", where);
        abortProgramNow(1);
    }
}

bool bufferqueueTryPushBack(buffer_queue_t *self, sbuf_t **b)
{
    if (UNLIKELY(! bufferqueueReserveExtra(self, 1)))
    {
        return false;
    }

    sbuf_t *entry = *b;

    // Only now: this destroys the caller's allocation in Debug builds.
    BUFFER_WONT_BE_REUSED(entry);
    bufferqueueInsertReserved((sbuf_t *) ww_sbuffer_queue_t_push_back(&self->q, entry), "push back");
    self->total_len += sbufGetLength(entry);
    *b = entry;
    return true;
}

bool bufferqueueTryPushFront(buffer_queue_t *self, sbuf_t **b)
{
    if (UNLIKELY(! bufferqueueReserveExtra(self, 1)))
    {
        return false;
    }

    sbuf_t *entry = *b;

    BUFFER_WONT_BE_REUSED(entry);
    bufferqueueInsertReserved((sbuf_t *) ww_sbuffer_queue_t_push_front(&self->q, entry), "push front");
    self->total_len += sbufGetLength(entry);
    *b = entry;
    return true;
}

sbuf_t *bufferqueuePushBack(buffer_queue_t *self, sbuf_t *b)
{
    if (UNLIKELY(! bufferqueueTryPushBack(self, &b)))
    {
        printError("buffer queue: out of memory queueing %u byte(s) with no per-flow recovery path",
                   (unsigned int) sbufGetLength(b));
        abortProgramNow(1);
    }
    return b;
}

sbuf_t *bufferqueuePushFront(buffer_queue_t *self, sbuf_t *b)
{
    if (UNLIKELY(! bufferqueueTryPushFront(self, &b)))
    {
        printError("buffer queue: out of memory requeueing %u byte(s) with no per-flow recovery path",
                   (unsigned int) sbufGetLength(b));
        abortProgramNow(1);
    }
    return b;
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
