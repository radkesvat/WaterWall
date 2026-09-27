#pragma once

#include "buffer_pool.h"

/* Cold-path construction from an explicitly owned worker pool. Copies ordinary
 * tiers, cache-width policy and independent splice/waiting limits. Padding stays
 * at its construction default until BringUp propagates finalized chain geometry.
 * The caller must have exclusive access to the source pool and live global master
 * pools. A nonzero minimum_small preserves backend framing/MTU requirements. */
buffer_pool_t *devicePoolCreate(buffer_pool_t *worker_pool, uint32_t minimum_small);

/* Before publishing I/O threads, copy all four finalized padding values. Both
 * pools must be exclusively accessible; this helper never obtains worker TLS. */
void devicePoolUpdatePadding(buffer_pool_t *device_pool, buffer_pool_t *worker_pool);
