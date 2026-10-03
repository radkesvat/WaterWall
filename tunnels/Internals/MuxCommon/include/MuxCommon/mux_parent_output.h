#pragma once

#include "MuxCommon/mux_limits.h"

typedef struct mux_parent_output_s
{
    buffer_queue_t pending;
    /* Complete Ping/Pong frames may precede paused ordinary frames. Both queues
     * share charge and admission limits; no frame callback is interrupted. */
    buffer_queue_t keepalive_pending;
    size_t         charge;
    uint64_t       throttle_started_us;
    uint64_t       last_throttle_us;
    bool           transport_paused;
    bool           sources_throttled;
    bool           pumping;
    bool           notifying;
} mux_parent_output_t;

/* The boolean makes timestamp zero a valid start. Time comes from the owner loop. */
static inline void muxParentOutputSetThrottled(mux_parent_output_t *output, bool throttled, uint64_t now_us)
{
    assert(output->sources_throttled != throttled);
    if (throttled)
        output->throttle_started_us = now_us;
    else
        output->last_throttle_us = now_us - output->throttle_started_us;
    output->sources_throttled = throttled;
}

static inline uint64_t muxParentOutputThrottleMS(const mux_parent_output_t *output, uint64_t now_us)
{
    return output->sources_throttled ? (now_us - output->throttle_started_us) / 1000 : 0;
}

/* Transactional admission; equality with the resource limit is permitted.
 * Failure preserves the supplied candidate, queue, and all counters. Preparation
 * (including any earlier ordinary fallback) belongs to the caller. Ordinary Debug
 * replacement preserves allocation geometry; Debug checks the retained pointer
 * before publishing the precomputed cost. */
static inline bool muxParentOutputEnqueueInto(mux_parent_output_t *output, buffer_queue_t *queue, sbuf_t **buf,
                                              size_t limit)
{
    size_t cost;
    if (UNLIKELY(! sbufTryGetQueueCharge(*buf, &cost) || output->charge > limit || cost > limit - output->charge ||
                 ! bufferqueueTryPushBack(queue, buf)))
        return false;

    assert(sbufGetQueueCharge(*buf) == cost);
    output->charge += cost;
    return true;
}

static inline bool muxParentOutputEnqueue(mux_parent_output_t *output, sbuf_t **buf, size_t limit)
{
    return muxParentOutputEnqueueInto(output, &output->pending, buf, limit);
}

static inline bool muxParentOutputEnqueueKeepalive(mux_parent_output_t *output, sbuf_t **buf, size_t limit)
{
    return muxParentOutputEnqueueInto(output, &output->keepalive_pending, buf, limit);
}

static inline sbuf_t *muxParentOutputPopFrom(mux_parent_output_t *output, buffer_queue_t *queue)
{
    sbuf_t *buf = bufferqueuePopFront(queue);
    assert(buf != NULL);
    const size_t cost = sbufGetQueueCharge(buf);
    if (UNLIKELY(output->charge < cost))
    {
        printError("Mux: parent output resource charge underflow");
        abortProgramNow(1);
    }
    output->charge -= cost;
    return buf;
}

static inline sbuf_t *muxParentOutputPop(mux_parent_output_t *output)
{
    return muxParentOutputPopFrom(output, &output->pending);
}

static inline sbuf_t *muxParentOutputPopKeepalive(mux_parent_output_t *output)
{
    return muxParentOutputPopFrom(output, &output->keepalive_pending);
}

static inline void muxParentOutputDestroy(mux_parent_output_t *output, buffer_pool_t *pool)
{
    const size_t discarded = muxDiscardRetainedQueue(&output->pending, pool);
    const size_t controls  = muxDiscardRetainedQueue(&output->keepalive_pending, pool);
    if (UNLIKELY(discarded > output->charge || controls != output->charge - discarded))
    {
        printError("Mux: parent output resource charge disagrees with queued ownership");
        abortProgramNow(1);
    }
    output->charge = 0;
    bufferqueueDestroy(&output->pending);
    bufferqueueDestroy(&output->keepalive_pending);
}

/* Small pooled controls must still carry the full onward chain headroom. */
static inline sbuf_t *muxParentOutputControlBuffer(buffer_pool_t *pool)
{
    const uint16_t padding = bufferpoolGetLargeBufferPadding(pool);
    if (bufferpoolGetSmallBufferPadding(pool) >= padding)
        return bufferpoolGetSmallBuffer(pool);
    return bufferpoolTryGetBestFit(pool, 0, padding);
}
