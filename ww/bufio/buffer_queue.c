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
    self->q            = ww_sbuffer_queue_t_init();
    self->total_len    = 0;
    self->total_charge = 0;
    self->budget       = NULL;
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

    if (self->budget != NULL)
        bufferbudgetRelease(self->budget,
                            (buffer_budget_cost_t) {self->total_len, self->total_charge, bufferqueueGetBufCount(self)});
    ww_sbuffer_queue_t_drop(&self->q);
    bufferqueueInitEmpty(self);
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

static sbuf_t *bufferqueueTakeBuffer(sbuf_t *buf)
{
    if (sbufIsSplice(buf))
    {
        // Its private pipe already owns the body; ordinary duplication would copy metadata as payload.
    }
    else
    {
        BUFFER_WONT_BE_REUSED(buf);
    }
    return buf;
}

bool bufferqueueTryAttachBudget(buffer_queue_t *self, buffer_budget_t *budget)
{
    assert(self->budget == NULL && budget != NULL);
    if (! bufferbudgetTryAcquire(
            budget, (buffer_budget_cost_t) {self->total_len, self->total_charge, bufferqueueGetBufCount(self)}))
        return false;
    self->budget = budget;
    return true;
}

static bool bufferqueueTryInsert(buffer_queue_t *self, sbuf_t **b, bool front, buffer_budget_reservation_t *reservation)
{
    buffer_budget_cost_t cost;
    if (! bufferbudgetTryGetCost(*b, &cost) || self->total_charge > SIZE_MAX - cost.charge ||
        self->total_len > SIZE_MAX - cost.bytes)
        return false;
    if (reservation != NULL)
    {
        assert(self->budget != NULL && reservation->budget == self->budget);
        assert(reservation->cost.bytes == cost.bytes && reservation->cost.charge == cost.charge &&
               reservation->cost.entries == cost.entries);
    }
    else if (self->budget != NULL && ! bufferbudgetTryAcquire(self->budget, cost))
        return false;

    if (! bufferqueueReserveExtra(self, 1))
    {
        if (self->budget != NULL && reservation == NULL)
            bufferbudgetRelease(self->budget, cost);
        return false;
    }
    // All fallible steps precede Debug allocation replacement.
    sbuf_t *entry = bufferqueueTakeBuffer(*b);
    assert(sbufGetQueueCharge(entry) == cost.charge);
    sbuf_t **slot =
        front ? ww_sbuffer_queue_t_push_front(&self->q, entry) : ww_sbuffer_queue_t_push_back(&self->q, entry);
    bufferqueueInsertReserved((sbuf_t *) slot, "insert");
    self->total_len += cost.bytes;
    self->total_charge += cost.charge;
    if (reservation != NULL)
        *reservation = (buffer_budget_reservation_t) {0};
    *b = entry;
    return true;
}

bool bufferqueueTryPushBack(buffer_queue_t *self, sbuf_t **b)
{
    return bufferqueueTryInsert(self, b, false, NULL);
}

bool bufferqueueTryPushFront(buffer_queue_t *self, sbuf_t **b)
{
    return bufferqueueTryInsert(self, b, true, NULL);
}

bool bufferqueueTryPushBackReserved(buffer_queue_t *self, sbuf_t **b, buffer_budget_reservation_t *reservation)
{
    return bufferqueueTryInsert(self, b, false, reservation);
}

bool bufferqueueTryPushFrontReserved(buffer_queue_t *self, sbuf_t **b, buffer_budget_reservation_t *reservation)
{
    return bufferqueueTryInsert(self, b, true, reservation);
}

sbuf_t *bufferqueuePushBack(buffer_queue_t *self, sbuf_t *b)
{
    if (UNLIKELY(! bufferqueueTryPushBack(self, &b)))
    {
        printError("buffer queue: failed to admit %u byte(s) with no per-flow recovery path",
                   (unsigned int) sbufGetLength(b));
        abortProgramNow(1);
    }
    return b;
}

sbuf_t *bufferqueuePushFront(buffer_queue_t *self, sbuf_t *b)
{
    if (UNLIKELY(! bufferqueueTryPushFront(self, &b)))
    {
        printError("buffer queue: failed to readmit %u byte(s) with no per-flow recovery path",
                   (unsigned int) sbufGetLength(b));
        abortProgramNow(1);
    }
    return b;
}

static sbuf_t *bufferqueuePop(buffer_queue_t *self, buffer_budget_reservation_t *reservation)
{
    if (UNLIKELY(ww_sbuffer_queue_t_size(&self->q) == 0))
    {
        return NULL;
    }
    sbuf_t      *b      = ww_sbuffer_queue_t_pull_front(&self->q);
    const size_t charge = sbufGetQueueCharge(b);
    assert(self->total_len >= sbufGetLength(b) && self->total_charge >= charge);
    self->total_len -= sbufGetLength(b);
    self->total_charge -= charge;
    if (self->budget != NULL)
    {
        buffer_budget_cost_t cost = {sbufGetLength(b), charge, 1};
        if (reservation != NULL)
            *reservation = (buffer_budget_reservation_t) {self->budget, cost};
        else
            bufferbudgetRelease(self->budget, cost);
    }
    return b;
}

sbuf_t *bufferqueuePopFront(buffer_queue_t *self)
{
    return bufferqueuePop(self, NULL);
}

sbuf_t *bufferqueuePopFrontReserved(buffer_queue_t *self, buffer_budget_reservation_t *reservation)
{
    assert(self->budget != NULL && reservation->budget == NULL);
    return bufferqueuePop(self, reservation);
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

size_t bufferqueueGetCharge(const buffer_queue_t *self)
{
    return self->total_charge;
}
