#pragma once

#include "MuxCommon/mux_limits.h"

typedef struct mux_parent_output_s
{
    buffer_queue_t pending;
    size_t         charge;
    bool           transport_paused;
    bool           sources_throttled;
    bool           pumping;
    bool           notifying;
} mux_parent_output_t;

/* Transactional admission; equality with the resource limit is permitted.
 * Failure preserves the supplied candidate, queue, and all counters. Preparation
 * (including any earlier ordinary fallback) belongs to the caller. Ordinary Debug
 * replacement preserves allocation geometry; Debug checks the retained pointer
 * before publishing the precomputed cost. */
static inline bool muxParentOutputEnqueue(mux_parent_output_t *output, sbuf_t **buf, size_t limit)
{
    size_t cost;
    if (! sbufTryGetQueueCharge(*buf, &cost) || output->charge > limit || cost > limit - output->charge ||
        ! bufferqueueTryPushBack(&output->pending, buf))
        return false;

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

/* Small pooled controls must still carry the full onward chain headroom. */
static inline sbuf_t *muxParentOutputControlBuffer(buffer_pool_t *pool)
{
    const uint16_t padding = bufferpoolGetLargeBufferPadding(pool);
    if (bufferpoolGetSmallBufferPadding(pool) >= padding)
        return bufferpoolGetSmallBuffer(pool);
    return bufferpoolTryGetBestFit(pool, 0, padding);
}
