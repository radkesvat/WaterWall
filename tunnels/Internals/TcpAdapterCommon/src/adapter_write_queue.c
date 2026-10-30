#include "TcpAdapterCommon/adapter_write_queue.h"

void awqInit(adapter_write_queue_t *q, bool blocked)
{
    assert(q != NULL);
    q->queue      = bufferqueueCreate(2);
    q->active     = (buffer_budget_reservation_t) {0};
    q->blocked    = blocked;
    q->pause_sent = false;
    bufferbudgetInit(&q->budget, (buffer_budget_cost_t) {kAwqMaxRetained, kAwqMaxRetained, SIZE_MAX});
    const bool attached = bufferqueueTryAttachBudget(&q->queue, &q->budget);
    assert(attached);
    discard attached;
}

void awqDestroy(adapter_write_queue_t *q)
{
    assert(q != NULL);
    bufferqueueDestroy(&q->queue);
    bufferbudgetReservationRelease(&q->active);
    bufferbudgetAssertEmpty(&q->budget);
    q->blocked    = false;
    q->pause_sent = false;
}

awq_admit_result_t awqAdmit(adapter_write_queue_t *q, buffer_pool_t *pool, sbuf_t **buf)
{
    assert(q != NULL && pool != NULL && buf != NULL && *buf != NULL);
    if (q->blocked)
    {
        if (! bufferqueueTryPushBack(&q->queue, buf))
        {
            bufferpoolReuseBuffer(pool, *buf);
            *buf = NULL;
            return kAwqOverflow;
        }
        *buf                             = NULL;
        const buffer_budget_cost_t usage = awqGetUsage(q);
        if ((usage.bytes >= kAwqPauseThreshold || usage.charge >= kAwqPauseThreshold) && awqTakePause(q))
            return kAwqQueuedPause;
        return kAwqQueued;
    }

    if (! bufferbudgetTryReserve(&q->budget, *buf, &q->active))
    {
        bufferpoolReuseBuffer(pool, *buf);
        *buf = NULL;
        return kAwqOverflow;
    }
    if (sbufGetLength(*buf) == 0)
    {
        bufferbudgetReservationRelease(&q->active);
        bufferpoolReuseBuffer(pool, *buf);
        *buf = NULL;
        return kAwqConsumed;
    }
    return kAwqWriteNow;
}

awq_write_result_t awqAfterWrite(adapter_write_queue_t *q, int nwrite, uint32_t bytes, size_t pending)
{
    assert(q != NULL && q->active.budget != NULL && bytes != 0);
    assert(nwrite < 0 || (uint32_t) nwrite <= bytes);
    awqRefreshPending(q, pending);
    if (nwrite < 0)
    {
        /* Close may be asynchronous. Further admitted payload must queue behind
         * this terminal reservation instead of trying to reserve it again. */
        q->blocked = true;
        return kAwqWriteFailed;
    }
    if ((uint32_t) nwrite < bytes)
    {
        q->blocked = true;
        return kAwqWriteBlocked;
    }
    awqReleaseCompleted(q);
    return kAwqWriteComplete;
}

sbuf_t *awqNextToWrite(adapter_write_queue_t *q, buffer_pool_t *pool)
{
    assert(q != NULL && pool != NULL && q->active.budget == NULL);
    sbuf_t *buf;
    while ((buf = bufferqueuePopFrontReserved(&q->queue, &q->active)) != NULL)
    {
        if (sbufGetLength(buf) != 0)
            return buf;
        bufferpoolReuseBuffer(pool, buf);
        awqReleaseCompleted(q);
    }
    q->blocked = false;
    return NULL;
}

sbuf_t *awqPopForFinish(adapter_write_queue_t *q, buffer_pool_t *pool)
{
    assert(q != NULL && pool != NULL);
    sbuf_t *buf;
    while ((buf = bufferqueuePopFront(&q->queue)) != NULL)
    {
        if (sbufGetLength(buf) != 0)
            return buf;
        bufferpoolReuseBuffer(pool, buf);
    }
    return NULL;
}
