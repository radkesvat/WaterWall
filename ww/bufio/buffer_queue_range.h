#pragma once

#include "buffer_pool.h"
#include "buffer_queue.h"

/** Consume exactly bytes in FIFO order from an owned active head and unbound
 * queued tail. All storage and the pool belong to the current worker. The active
 * head may be NULL; otherwise it is exclusively owned and is not still queued.
 * The caller guarantees complete availability and representable ordinary output
 * geometry, including the pool's large-buffer padding.
 *
 * Returns the sole owned output with full onward padding. A suitable whole head
 * transfers directly; assembly selects splice when any participating source
 * wrapper is splice-backed, even if only its resident prefix is requested.
 * Unavailable pipes or pipe pressure fall back to complete ordinary storage.
 * Sources are popped before mutation, exhausted heads are recycled, and the
 * unrequested suffix stays in active_head/tail. bytes == 0 returns one empty
 * ordinary output without changing either input owner.
 *
 * No callbacks occur. The caller retains protocol metadata, logical-byte policy,
 * admission and cleanup responsibilities. Budget-bound queues are not supported:
 * their active storage requires reservation accounting beyond ordinary pop.
 */
sbuf_t *bufferRangeTakeExact(buffer_pool_t *pool, sbuf_t **active_head, buffer_queue_t *tail, uint32_t bytes);
