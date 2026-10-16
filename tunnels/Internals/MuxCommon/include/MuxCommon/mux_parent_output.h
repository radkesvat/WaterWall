#pragma once

#include "MuxCommon/mux_limits.h"

typedef struct mux_parent_output_s
{
    buffer_queue_t pending;
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

/* Transactional admission to an unbound queue; equality with the resource limit is permitted.
 * Failure preserves the supplied candidate, queue, and all counters. Preparation
 * (including any earlier ordinary fallback) belongs to the caller. Ordinary Debug
 * replacement preserves allocation geometry; Debug checks the retained pointer
 * before publishing the precomputed cost. */
static inline bool muxParentOutputEnqueue(mux_parent_output_t *output, sbuf_t **buf, size_t limit)
{
    assert(output->pending.budget == NULL);
    size_t cost;
    if (UNLIKELY(! sbufTryGetQueueCharge(*buf, &cost) || output->charge > limit || cost > limit - output->charge))
        return false;

    /* Charge covers payload and at least 64 bytes per entry, so admission also
     * bounds byte totals and deque geometry on 32-bit and 64-bit targets. */
    *buf = bufferqueuePushBack(&output->pending, *buf);
    assert(sbufGetQueueCharge(*buf) == cost);
    output->charge += cost;
    return true;
}

static inline sbuf_t *muxParentOutputPop(mux_parent_output_t *output)
{
    sbuf_t *buf = bufferqueuePopFront(&output->pending);
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

static inline void muxParentOutputDestroy(mux_parent_output_t *output, buffer_pool_t *pool)
{
    const size_t discarded = muxDiscardRetainedQueue(&output->pending, pool);
    if (UNLIKELY(discarded != output->charge))
    {
        printError("Mux: parent output resource charge disagrees with queued ownership");
        abortProgramNow(1);
    }
    output->charge -= discarded;
    bufferqueueDestroy(&output->pending);
}

/* Controls carry the full onward chain headroom. A valid pool's large tier
 * always satisfies this zero-payload request, so the result is non-NULL. */
static inline sbuf_t *muxParentOutputControlBuffer(buffer_pool_t *pool)
{
    const uint16_t padding = bufferpoolGetLargeBufferPadding(pool);
    if (bufferpoolGetSmallBufferPadding(pool) >= padding)
        return bufferpoolGetSmallBuffer(pool);
    return bufferpoolGetBestFit(pool, 0, padding);
}
