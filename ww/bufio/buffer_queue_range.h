#pragma once

#include "buffer_pool.h"
#include "buffer_queue.h"

/** Gather a prefix into caller-owned resident storage from an owned active head
 * and unbound queued tail. All storage and the pool belong to the current worker.
 * The active head may be NULL; otherwise it is exclusively owned and not queued.
 * The caller provides writable dst storage through needed bytes and preserves
 * the already-filled prefix. Protocol metadata and logical-byte accounting remain
 * with the caller; budget-bound queues require separate reservation accounting.
 *
 * Returns true when *filled >= needed, leaving both input owners unchanged when
 * that condition already holds. Otherwise consumes only the missing bytes,
 * including private-pipe bytes, popping entries before mutation and recycling
 * exhausted heads through pool. False means input ran out; copied bytes and the
 * updated *filled remain committed for the next call. Any unread suffix remains
 * in active_head/tail. No callbacks or allocations occur.
 */
bool bufferRangeGatherPrefix(buffer_pool_t *pool, sbuf_t **active_head, buffer_queue_t *tail, uint8_t *dst,
                             uint16_t *filled, uint16_t needed);

/** Restore only an owned active head's unread suffix to the front of an unbound
 * tail, then clear *active_head. A NULL head is a no-op. Storage belongs to the
 * current worker and the head must not already be queued. Consumed prefix bytes
 * remain the caller's responsibility; this operation does not reconstruct them.
 *
 * The caller proves readmission fits the queue's byte/charge totals and entry
 * storage, for example by only consuming a previously popped head without any
 * intervening admission. Uses the fail-fast queue insertion contract. It may
 * allocate queue storage or replace an ordinary buffer in Debug; no callbacks
 * occur and no alias to the transferred head may be retained.
 */
void bufferRangeRestoreHead(sbuf_t **active_head, buffer_queue_t *tail);

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
