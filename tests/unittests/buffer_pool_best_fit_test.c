#include "wwapi.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static void testMediumPoolGeometry(uint32_t large_size)
{
    master_pool_t *masters[4];
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
        masters[i] = masterpoolCreateWithCapacity(32);
    buffer_pool_t *pool = bufferpoolCreate(masters[0], masters[1], masters[2], masters[3], 2, large_size, 4096);
    require(pool != NULL, "medium test pool construction failed");
    bufferpoolUpdateAllocationPaddings(pool, 32, 32, 32, 32);

    sbuf_t *best = bufferpoolGetBestFit(pool, 4097, 32);
    require(sbufGetTotalCapacityNoPadding(best) == MEDIUM_BUFFER_SIZE,
            "best fit skipped medium storage for a frame larger than small capacity");
    bufferpoolReuseBuffer(pool, best);
    if (large_size > MEDIUM_BUFFER_SIZE)
    {
        best = bufferpoolGetBestFit(pool, MEDIUM_BUFFER_SIZE + 1, 32);
        require(sbufGetTotalCapacityNoPadding(best) == large_size,
                "best fit truncated a payload above medium capacity");
        bufferpoolReuseBuffer(pool, best);
    }

    sbuf_t *buffers[16];
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        buffers[i] = bufferpoolGetMediumBuffer(pool);
        require(sbufGetTotalCapacityNoPadding(buffers[i]) == MEDIUM_BUFFER_SIZE,
                "medium size changed with large geometry");
        sbufSetLength(buffers[i], 40);
        sbufShiftLeft(buffers[i], 8);
    }
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
        bufferpoolReuseBuffer(pool, buffers[i]);

    master_pool_t *retained_master = large_size == MEDIUM_BUFFER_SIZE ? masters[0] : masters[1];
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
    buffer_pool_t *other = bufferpoolCreate(masters[0], masters[1], masters[2], masters[3], 1, large_size, 4096);
    bufferpoolUpdateAllocationPaddings(other, 96, 96, 32, 32);
    sbuf_t *padded = bufferpoolGetMediumBuffer(other);
    require(sbufGetTotalCapacityNoPadding(padded) == MEDIUM_BUFFER_SIZE && sbufGetLeftCapacity(padded) == 96,
            "shared medium checkout retained incompatible padding");
    bufferpoolReuseBuffer(other, padded);
    bufferpoolDestroy(other);
    bufferpoolDestroy(pool);
    for (size_t i = 0; i < ARRAY_SIZE(masters); ++i)
    {
        masterpoolMakeEmpty(masters[i]);
        masterpoolDestroy(masters[i]);
    }
}

int main(void)
{
    require(PROPER_LARGE_BUFFER_SIZE(kRamProfileS1Memory) == 4096 &&
                PROPER_LARGE_BUFFER_SIZE(kRamProfileS2Memory) == 4096,
            "low-memory profiles lost their 4 KiB read buffers");
    require(PROPER_LARGE_BUFFER_SIZE(kRamProfileM1Memory) == 512 * 1024 &&
                PROPER_LARGE_BUFFER_SIZE(kRamProfileL2Memory) == 512 * 1024,
            "higher memory profiles do not use 512 KiB read buffers");
    testMediumPoolGeometry(4096);
    testMediumPoolGeometry(64 * 1024);
    testMediumPoolGeometry(512 * 1024);
    master_pool_t *large_master = masterpoolCreateWithCapacity(8);
    master_pool_t *small_master = masterpoolCreateWithCapacity(8);
    master_pool_t *medium_master = masterpoolCreateWithCapacity(8);
    master_pool_t *splice_master = masterpoolCreateWithCapacity(8);
    buffer_pool_t *pool = bufferpoolCreate(large_master, medium_master, small_master, splice_master, 8, 8192, 1024);
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
    require(sbufGetTotalCapacityNoPadding(size_fallback) == MEDIUM_BUFFER_SIZE,
            "best fit did not use the fixed medium tier above the smaller large tier");
    bufferpoolReuseBuffer(pool, size_fallback);

    sbuf_t *medium = bufferpoolGetMediumBuffer(pool);
    require(medium == size_fallback && sbufGetLength(medium) == 0 && sbufGetLeftPadding(medium) == 64,
            "medium checkout did not reuse/reset the pooled allocation");
    require(bufferpoolGetMediumBufferSize(pool) == 64 * 1024,
            "medium capacity followed the low-memory large-buffer size");
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
