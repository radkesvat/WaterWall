#pragma once

#include "wwapi.h"

typedef struct mux_parent_output_s
{
    buffer_queue_t pending;
    size_t         charge;
    bool           transport_paused;
    bool           sources_throttled;
    bool           pumping;
    bool           notifying;
} mux_parent_output_t;

/* Transactional admission; equality with the limit is permitted. Ordinary Debug
 * replacement preserves capacity and padding because sbuf allocations are already
 * rounded. Check the returned allocation, never an alias of the replaced buffer. */
static inline bool muxParentOutputEnqueue(mux_parent_output_t *output, sbuf_t **buf, size_t limit)
{
    const size_t charge = sbufGetAllocationCharge(*buf);
    if (output->charge > limit || charge > limit - output->charge || ! bufferqueueTryPushBack(&output->pending, buf))
    {
        return false;
    }
    assert(sbufGetAllocationCharge(*buf) == charge);
    output->charge += sbufGetAllocationCharge(*buf);
    return true;
}

static inline sbuf_t *muxParentOutputPop(mux_parent_output_t *output)
{
    sbuf_t *buf = bufferqueuePopFront(&output->pending);
    assert(buf != NULL);
    const size_t charge = sbufGetAllocationCharge(buf);
    assert(output->charge >= charge);
    output->charge -= charge;
    return buf;
}

/* Small pooled controls must still carry the full onward chain headroom. */
static inline sbuf_t *muxParentOutputControlBuffer(buffer_pool_t *pool)
{
    const uint16_t padding = bufferpoolGetLargeBufferPadding(pool);
    if (bufferpoolGetSmallBufferPadding(pool) >= padding)
        return bufferpoolGetSmallBuffer(pool);
    return bufferpoolTryGetBestFit(pool, 0, padding);
}
