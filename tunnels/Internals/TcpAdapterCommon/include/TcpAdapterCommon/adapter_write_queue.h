#pragma once

#include "buffer_pool.h"
#include "buffer_queue.h"

enum
{
    kAwqMaxRetained    = 1U << 24,
    kAwqPauseThreshold = 1U << 10
};

typedef enum awq_admit_result_e
{
    kAwqWriteNow,
    kAwqQueued,
    kAwqQueuedPause,
    kAwqConsumed,
    kAwqOverflow
} awq_admit_result_t;

typedef enum awq_write_result_e
{
    kAwqWriteComplete,
    kAwqWriteBlocked,
    kAwqWriteFailed
} awq_write_result_t;

/* Embed at its final stable address before Init: queue and active borrow budget.
 * All operations belong to the owning event worker. The FIFO owns its buffers;
 * active owns accounting only, never the buffer transferred to WIO. No socket
 * I/O, line access or callbacks; recycling may discard private splice bodies.
 * Fields are private to the helper. */
typedef struct adapter_write_queue_s
{
    buffer_queue_t              queue;
    buffer_budget_t             budget;
    buffer_budget_reservation_t active;
    bool                        blocked : 1;
    bool                        pause_sent : 1;
} adapter_write_queue_t;

/* Requires fresh storage or a destroyed queue. Connecting sockets start blocked. */
void awqInit(adapter_write_queue_t *q, bool blocked);

/* Recycles queued ownership and settles accounting, including active WIO cost.
 * Caller must first detach callbacks that could reach this state. Never recycles
 * the active buffer: WIO independently owns and settles it. */
void awqDestroy(adapter_write_queue_t *q);

/* Refresh before admission, after a live write return, and on partial completion.
 * pending is WIO's byte count, not an observation of the transferred buffer.
 * Only bytes decrease; original allocation charge and entry remain reserved. */
static inline void awqRefreshPending(adapter_write_queue_t *q, size_t pending)
{
    assert(q != NULL);
    if (q->active.budget != NULL)
        bufferbudgetReservationSetBytes(&q->active, pending);
}

/* Consumes and clears *buf on every result except WriteNow, which leaves the
 * caller owning that exact buffer with its active cost reserved for transfer to
 * WIO. Refusal recycles once. Paused empty inputs remain charged FIFO entries;
 * direct empty inputs undergo admission, then recycle without a socket write.
 * QueuedPause has already published ownership, accounting and the Pause latch. */
WW_MUST_USE awq_admit_result_t awqAdmit(adapter_write_queue_t *q, buffer_pool_t *pool, sbuf_t **buf);

/* Caller has revalidated state after its write. Failure blocks further direct
 * writes and keeps active accounting until terminal cleanup; success releases
 * it only for a complete write.
 * A short write blocks further direct admission but does not consume Pause:
 * direct writers call TakePause; resumed FIFO drains retain their prior latch. */
WW_MUST_USE awq_write_result_t awqAfterWrite(adapter_write_queue_t *q, int nwrite, uint32_t bytes, size_t pending);

static inline bool awqTakePause(adapter_write_queue_t *q)
{
    assert(q != NULL && q->blocked);
    if (q->pause_sent)
        return false;
    q->pause_sent = true;
    return true;
}

/* Only after the caller proves WIO complete and refreshes its zero pending bytes.
 * Empty release is safe; charge is never released merely for partial progress. */
static inline void awqReleaseCompleted(adapter_write_queue_t *q)
{
    assert(q != NULL && q->active.cost.bytes == 0);
    bufferbudgetReservationRelease(&q->active);
}

/* Requires no active reservation. Transfers the next nonempty buffer with its
 * accounting still reserved; skips/recycles empty entries. Exhaustion unblocks
 * direct writes but leaves the Pause latch for a separately revalidated Resume. */
sbuf_t *awqNextToWrite(adapter_write_queue_t *q, buffer_pool_t *pool);

/* Connector calls this only after Est and its life/pressure rechecks. Publish
 * the cleared latch before dispatching the Resume, which may reenter or close. */
static inline bool awqTakeResume(adapter_write_queue_t *q)
{
    assert(q != NULL);
    if (q->blocked || ! q->pause_sent)
        return false;
    q->pause_sent = false;
    return true;
}

/* Terminal path only, after node-side callback detachment. Releases each FIFO
 * cost before returning owned nonempty input; skips/recycles empty entries.
 * Does not acquire active cost, unblock writes, or consume the Pause latch. */
sbuf_t *awqPopForFinish(adapter_write_queue_t *q, buffer_pool_t *pool);

static inline bool awqIsBlocked(const adapter_write_queue_t *q)
{
    assert(q != NULL);
    return q->blocked;
}

static inline size_t awqGetQueuedBytes(adapter_write_queue_t *q)
{
    assert(q != NULL);
    return bufferqueueGetBufLen(&q->queue);
}

static inline buffer_budget_cost_t awqGetUsage(const adapter_write_queue_t *q)
{
    assert(q != NULL);
    return bufferbudgetGetUsage(&q->budget);
}
