#include "buffer_pool_internal.h"
#include "wwapi.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void testMediumPoolGeometry(uint32_t large_size, uint32_t medium_size)
{
    master_pool_t *masters[4];
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
        masters[i] = masterpoolCreateWithCapacity(32);
    buffer_pool_t *pool =
        bufferpoolCreate(masters[0], masters[1], masters[2], masters[3], 2, large_size, medium_size, 4096);
    require(pool != NULL, "medium test pool construction failed");
    bufferpoolUpdateAllocationPaddings(pool, 32, 32, 32, 32);

    sbuf_t *best = bufferpoolGetBestFit(pool, 4097, 32);
    require(sbufGetTotalCapacityNoPadding(best) == medium_size,
            "best fit skipped medium storage for a frame larger than small capacity");
    bufferpoolReuseBuffer(pool, best);
    if (large_size > medium_size)
    {
        best = bufferpoolGetBestFit(pool, medium_size + 1, 32);
        require(sbufGetTotalCapacityNoPadding(best) == large_size,
                "best fit truncated a payload above medium capacity");
        bufferpoolReuseBuffer(pool, best);
    }

    sbuf_t *buffers[16];
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        buffers[i] = bufferpoolGetMediumBuffer(pool);
        require(sbufGetTotalCapacityNoPadding(buffers[i]) == medium_size, "medium size changed with large geometry");
        sbufSetLength(buffers[i], 40);
        sbufShiftLeft(buffers[i], 8);
    }
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
        bufferpoolReuseBuffer(pool, buffers[i]);

    master_pool_t *retained_master = large_size == medium_size ? masters[0] : masters[1];
    require(atomicLoadRelaxed(&retained_master->len) > 0, "medium returns never reached the shared master");
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        buffers[i] = bufferpoolGetMediumBuffer(pool);
        require(sbufGetLength(buffers[i]) == 0 && sbufGetLeftCapacity(buffers[i]) == 32,
                "medium reuse did not restore its length and headroom");
    }
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
        bufferpoolReuseBuffer(pool, buffers[i]);

    // Shared masters may contain buffers padded for another worker/device pool.
    const uint32_t other_medium_size = medium_size == 32 * 1024 ? 64 * 1024 : 32 * 1024;
    buffer_pool_t *other =
        bufferpoolCreate(masters[0], masters[1], masters[2], masters[3], 1, large_size, other_medium_size, 4096);
    bufferpoolUpdateAllocationPaddings(other, 96, 96, 32, 32);
    sbuf_t *padded = bufferpoolGetMediumBuffer(other);
    require(sbufGetTotalCapacityNoPadding(padded) == other_medium_size && sbufGetLeftCapacity(padded) == 96,
            "shared medium checkout retained incompatible capacity or padding");
    bufferpoolReuseBuffer(other, padded);
    bufferpoolDestroy(other);
    bufferpoolDestroy(pool);
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
    {
        masterpoolMakeEmpty(masters[i]);
        masterpoolDestroy(masters[i]);
    }
}

static void testLowProfilePoolWidths(void)
{
    const uint32_t profiles[] = {kRamProfileS1Memory, kRamProfileS2Memory};
    for (size_t i = 0; i < ARRAY_SIZE(profiles); ++i)
    {
        master_pool_t *masters[4];
        for (size_t j = 0; j < ARRAY_SIZE(masters); ++j)
            masters[j] = masterpoolCreateWithCapacity(2 * profiles[i]);
        buffer_pool_t *pool = bufferpoolCreate(masters[0],
                                               masters[1],
                                               masters[2],
                                               masters[3],
                                               profiles[i],
                                               PROPER_LARGE_BUFFER_SIZE(profiles[i]),
                                               PROPER_MEDIUM_BUFFER_SIZE(profiles[i]),
                                               SMALL_BUFFER_SIZE);
        require(pool != NULL, "could not create low-profile pool");
        sbuf_t *small  = bufferpoolGetSmallBuffer(pool);
        sbuf_t *medium = bufferpoolGetMediumBuffer(pool);
        sbuf_t *large  = bufferpoolGetLargeBuffer(pool);
        require(sbufGetTotalCapacityNoPadding(small) == 4096 && sbufGetTotalCapacityNoPadding(medium) == 32 * 1024 &&
                    sbufGetTotalCapacityNoPadding(large) == 64 * 1024,
                "low-profile pool returned the wrong buffer geometry");
        uint32_t cached_large, cached_medium, cached_small, cached_splice;
        bufferpoolCachedTierCountsForTest(pool, &cached_large, &cached_small, &cached_splice, &cached_medium);
        require(cached_large == profiles[i] - 1 && cached_medium == profiles[i] - 1 && cached_small == profiles[i] - 1,
                "S1/S2 local caches did not retain their profile-based recharge counts");
        bufferpoolReuseBuffer(pool, small);
        bufferpoolReuseBuffer(pool, medium);
        bufferpoolReuseBuffer(pool, large);
        bufferpoolDestroy(pool);
        for (size_t j = 0; j < ARRAY_SIZE(masters); ++j)
        {
            masterpoolMakeEmpty(masters[j]);
            masterpoolDestroy(masters[j]);
        }
    }
}

int main(void)
{
    testLowProfilePoolWidths();
    const uint32_t profiles[] = {kRamProfileS1Memory,
                                 kRamProfileS2Memory,
                                 kRamProfileM1Memory,
                                 kRamProfileM2Memory,
                                 kRamProfileL1Memory,
                                 kRamProfileL2Memory};
    for (size_t i = 0; i < ARRAY_SIZE(profiles); ++i)
    {
        const bool low = profiles[i] < kRamProfileM1Memory;
        require(PROPER_LARGE_BUFFER_SIZE(profiles[i]) == (low ? 64 * 1024 : 1024 * 1024),
                "profile has the wrong large-buffer capacity");
        require(PROPER_MEDIUM_BUFFER_SIZE(profiles[i]) == (low ? 32 * 1024 : 64 * 1024),
                "profile has the wrong medium-buffer capacity");
        testMediumPoolGeometry(PROPER_LARGE_BUFFER_SIZE(profiles[i]), PROPER_MEDIUM_BUFFER_SIZE(profiles[i]));
    }
    testMediumPoolGeometry(4096, 64 * 1024);
    testMediumPoolGeometry(64 * 1024, 64 * 1024);
    testMediumPoolGeometry(512 * 1024, 64 * 1024);
    master_pool_t *large_master = masterpoolCreateWithCapacity(8);
    master_pool_t *small_master = masterpoolCreateWithCapacity(8);
    master_pool_t *medium_master = masterpoolCreateWithCapacity(8);
    master_pool_t *splice_master = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool          = bufferpoolCreate(
        large_master, medium_master, small_master, splice_master, 8, 8192, MEDIUM_BUFFER_SIZE_RAM_HIGH, 1024);
    bufferpoolUpdateAllocationPaddings(pool, 64, 64, 32, 32);

    sbuf_t *tiny = bufferpoolGetBestFit(pool, 1, 0);
    require(sbufGetTotalCapacityNoPadding(tiny) == bufferpoolGetSmallBufferSize(pool),
            "best-fit allocation selected the explicit-only splice tier");
    bufferpoolReuseBuffer(pool, tiny);

    sbuf_t *small = bufferpoolGetBestFit(pool, 512, 16);
    require(sbufGetTotalCapacityNoPadding(small) == bufferpoolGetSmallBufferSize(pool),
            "best-fit allocator did not select the small tier");
    require(sbufGetLeftPadding(small) >= 16, "small best-fit buffer lacks requested padding");
    bufferpoolReuseBuffer(pool, small);

    sbuf_t *large = bufferpoolGetBestFit(pool, 4096, 48);
    require(sbufGetTotalCapacityNoPadding(large) == bufferpoolGetLargeBufferSize(pool),
            "best-fit allocator did not select the large tier");
    require(sbufGetLeftPadding(large) >= 48, "large best-fit buffer lacks requested padding");
    bufferpoolReuseBuffer(pool, large);

    sbuf_t *padding_fallback = bufferpoolGetBestFit(pool, 512, 96);
    require(sbufGetTotalCapacityNoPadding(padding_fallback) >= 512 && sbufGetLeftPadding(padding_fallback) >= 96,
            "best-fit padding fallback does not satisfy its geometry");
    require(sbufGetTotalCapacityNoPadding(padding_fallback) != bufferpoolGetSmallBufferSize(pool) ||
                sbufGetLeftPadding(padding_fallback) != bufferpoolGetSmallBufferPadding(pool),
            "best-fit allocator returned an unsuitable pooled buffer");
    bufferpoolReuseBuffer(pool, padding_fallback);

    sbuf_t *size_fallback = bufferpoolGetBestFit(pool, 16384, 24);
    require(sbufGetTotalCapacityNoPadding(size_fallback) >= 16384 && sbufGetLeftPadding(size_fallback) >= 24,
            "best-fit size fallback does not satisfy its geometry");
    require(sbufGetTotalCapacityNoPadding(size_fallback) == MEDIUM_BUFFER_SIZE_RAM_HIGH,
            "best fit did not use the fixed medium tier above the smaller large tier");
    bufferpoolReuseBuffer(pool, size_fallback);

    sbuf_t *medium = bufferpoolGetMediumBuffer(pool);
    require(medium == size_fallback && sbufGetLength(medium) == 0 && sbufGetLeftPadding(medium) == 64,
            "medium checkout did not reuse/reset the pooled allocation");
    require(bufferpoolGetMediumBufferSize(pool) == 64 * 1024,
            "explicit medium capacity changed with the custom large-buffer size");
    bufferpoolReuseBuffer(pool, medium);
    require(bufferpoolTryGetBestFit(pool, UINT64_MAX, 64) == NULL,
            "checked best fit accepted an unrepresentable computed length");

    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolMakeEmpty(medium_master);
    masterpoolMakeEmpty(splice_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);
    masterpoolDestroy(medium_master);
    masterpoolDestroy(splice_master);
    return 0;
}
