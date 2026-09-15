#include "wwapi.h"

#include "buffer_pool_internal.h"

#ifdef WW_SPLICE_POOL_FAILURE_TEST
static unsigned int fail_allocation;
void               *__real_memoryAllocate(size_t size);
void               *__wrap_memoryAllocate(size_t size);

void *__wrap_memoryAllocate(size_t size)
{
    if (fail_allocation != 0 && --fail_allocation == 0)
    {
        return NULL;
    }
    return __real_memoryAllocate(size);
}
#endif

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static uint32_t cachedSpliceCount(buffer_pool_t *pool)
{
    uint32_t large, small, splice;
    bufferpoolCachedTierCountsForTest(pool, &large, &small, &splice);
    require(large == 0 && small == 0, "splice operations touched the large/small caches");
    return splice;
}

static void checkSplice(sbuf_t *buffer, uint16_t padding)
{
    require(sbufGetTotalCapacityNoPadding(buffer) == SPLICE_BUFFER_STORAGE_SIZE,
            "splice buffer lost its physical control-storage capacity");
    require(sbufGetLeftPadding(buffer) == padding && sbufGetLeftCapacity(buffer) == padding,
            "splice buffer has incorrect padding or cursor");
    require(sbufGetLength(buffer) == 0 && buffer->flags == kSbufFlagSplice && sbufGetLifetime(buffer) == NULL,
            "splice checkout retained payload metadata");
}

static void testRechargeBatches(void)
{
    static const uint32_t widths[]              = {1, 2, 3, 4, 8, 256};
    sbuf_t *(*const getters[])(buffer_pool_t *) = {
        bufferpoolGetLargeBuffer, bufferpoolGetSmallBuffer, bufferpoolGetSpliceBuffer};

    for (size_t w = 0; w < ARRAY_SIZE(widths); ++w)
    {
        master_pool_t *masters[3];
        for (size_t tier = 0; tier < ARRAY_SIZE(masters); ++tier)
        {
            masters[tier] = masterpoolCreateWithCapacity(16);
            require(masters[tier] != NULL, "failed to create refill test master");
        }
        buffer_pool_t *pool = bufferpoolCreate(masters[0], masters[1], masters[2], widths[w], 8192, 1024);
        require(pool != NULL, "failed to create refill test pool");
        const uint32_t batch = min(widths[w], 4U);
        for (size_t tier = 0; tier < ARRAY_SIZE(getters); ++tier)
        {
            uint32_t before[3];
            bufferpoolCachedTierCountsForTest(pool, &before[0], &before[1], &before[2]);
            sbuf_t *buffers[8];
            // Hold the first batch to force a second refill of the same tier.
            for (uint32_t i = 0; i < batch * 2U; ++i)
            {
                buffers[i] = getters[tier](pool);
                uint32_t counts[3];
                bufferpoolCachedTierCountsForTest(pool, &counts[0], &counts[1], &counts[2]);
                require(counts[tier] == batch - 1U - i % batch, "refill exceeded its four-buffer or small-pool limit");
                for (size_t other = 0; other < ARRAY_SIZE(counts); ++other)
                {
                    if (other != tier)
                    {
                        require(counts[other] == before[other], "refill changed another tier's cache");
                    }
                }
            }
            for (uint32_t i = 0; i < batch * 2U; ++i)
            {
                bufferpoolReuseBuffer(pool, buffers[i]);
            }
        }
        bufferpoolDestroy(pool);
        for (size_t tier = 0; tier < ARRAY_SIZE(masters); ++tier)
        {
            masterpoolMakeEmpty(masters[tier]);
            masterpoolDestroy(masters[tier]);
        }
    }
}

int main(void)
{
    testRechargeBatches();
    master_pool_t *large = masterpoolCreateWithCapacity(16);
    master_pool_t *small = masterpoolCreateWithCapacity(16);
    master_pool_t *splice = masterpoolCreateWithCapacity(16);
    require(large != NULL && small != NULL && splice != NULL, "failed to create test master pools");
    require(bufferpoolCreate(large, small, NULL, 2, 4096, 512) == NULL, "missing splice master was accepted");

#ifdef WW_SPLICE_POOL_FAILURE_TEST
    const MasterPoolItemCreateHandle original_large = large->create_item_handle;
    const MasterPoolItemCreateHandle original_small = small->create_item_handle;
    const MasterPoolItemCreateHandle original_splice = splice->create_item_handle;
    for (unsigned int allocation = 1; allocation <= 4; ++allocation)
    {
        fail_allocation = allocation;
        require(bufferpoolCreate(large, small, splice, 2, 4096, 512) == NULL,
                "buffer pool metadata allocation failure was not returned");
        require(fail_allocation == 0, "metadata allocation failure was not exercised");
        require(large->create_item_handle == original_large && small->create_item_handle == original_small &&
                    splice->create_item_handle == original_splice,
                "failed construction published master callbacks");
    }
#endif

    buffer_pool_t *pool = bufferpoolCreate(large, small, splice, 2, 4096, 512);
    require(pool != NULL, "failed to create splice test pool");
    bufferpoolUpdateAllocationPaddings(pool, 64, 64, 33);
    require(bufferpoolGetSpliceBufferStorageSize(pool) == 32 && bufferpoolGetSpliceBufferPadding(pool) == 64,
            "splice tier getters reported incorrect geometry");
    require(cachedSpliceCount(pool) == 0, "splice cache was eagerly populated");

    sbuf_t *buffers[10];
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        buffers[i] = bufferpoolGetSpliceBuffer(pool);
        checkSplice(buffers[i], 64);
    }
    buffers[0]->flags    = kSbufFlagSplice | kSbufFlagSpliceFD;
    buffers[0]->capacity = 64 + 8192;
    buffers[0]->len      = 8192;
    sbufShiftLeft(buffers[0], 4);
    buffers[1]->flags    = kSbufFlagSplice | kSbufFlagSplicePiped;
    buffers[1]->capacity = 64 + 16384;
    buffers[1]->len      = 16384;
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        bufferpoolReuseBuffer(pool, buffers[i]);
    }
    require(cachedSpliceCount(pool) <= 4 && atomicLoadRelaxed(&splice->len) > 0,
            "splice cache did not shrink to its shared master");
    require(cachedSpliceCount(pool) + atomicLoadRelaxed(&splice->len) == ARRAY_SIZE(buffers),
            "recycling lost a splice buffer with virtual splice capacity");
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        buffers[i] = bufferpoolGetSpliceBuffer(pool);
        checkSplice(buffers[i], 64);
    }
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        bufferpoolReuseBuffer(pool, buffers[i]);
    }

    // A second pool can draw from the shared master while requiring different headroom.
    buffer_pool_t *other = bufferpoolCreate(large, small, splice, 1, 4096, 512);
    require(other != NULL, "failed to create the second splice pool");
    bufferpoolUpdateAllocationPaddings(other, 64, 64, 96);
    sbuf_t *buffer = bufferpoolGetSpliceBuffer(other);
    checkSplice(buffer, 96);
    bufferpoolReuseBuffer(other, buffer);

    bufferpoolDestroy(other);
    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large);
    masterpoolMakeEmpty(small);
    masterpoolMakeEmpty(splice);
    masterpoolDestroy(large);
    masterpoolDestroy(small);
    masterpoolDestroy(splice);
    return 0;
}
