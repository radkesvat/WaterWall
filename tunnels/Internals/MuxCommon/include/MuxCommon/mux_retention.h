#pragma once

#include "MuxCommon/mux_limits.h"
#include "MuxCommon/mux_wire.h"

/* Ordinary paused-child candidates may compact to a cheaper pooled tier.
 * Valid splice sources retain their representation independently of other queues. */
static inline sbuf_t *muxPrepareRetainedCandidate(buffer_pool_t *pool, sbuf_t *buf, bool compact_ordinary)
{
    return compact_ordinary ? muxPrepareQueuedPayload(pool, buf) : buf;
}

/* Child accounting stays separate from incoming ownership. Overflow is pressure,
 * not a wrapped total. A zero configured limit disables only the finite bound. */
static inline bool muxTryParentReceiveCharge(size_t children, const splice_stream_t *stream, size_t *charge)
{
    const size_t incoming = splicestreamCharge(stream);
    if (children > SIZE_MAX - incoming)
        return false;
    *charge = children + incoming;
    return true;
}

static inline bool muxParentReceiveOverLimit(size_t children, const splice_stream_t *stream, size_t limit)
{
    size_t total;
    return ! muxTryParentReceiveCharge(children, stream, &total) || (limit != 0 && total >= limit);
}
