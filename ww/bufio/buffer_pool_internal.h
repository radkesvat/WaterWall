#pragma once

#include <stdint.h>

typedef struct buffer_pool_s buffer_pool_t;

/* Test-only boundary seam for the otherwise private pool metadata object. */
uint64_t bufferpoolMetadataSizeForTest(void);

/* Test-only observation of the private tier caches; it does not mutate ownership. */
void bufferpoolCachedTierCountsForTest(const buffer_pool_t *pool, uint32_t *large_count, uint32_t *small_count);
