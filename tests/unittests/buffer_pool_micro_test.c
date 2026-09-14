#include "wwapi.h"

#include "buffer_pool_internal.h"

#ifdef WW_MICRO_POOL_FAILURE_TEST
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

static uint32_t cachedMicroCount(buffer_pool_t *pool)
{
    uint32_t large, small, micro;
    bufferpoolCachedTierCountsForTest(pool, &large, &small, &micro);
    require(large == 0 && small == 0, "micro operations touched the large/small caches");
    return micro;
}

static void checkMicro(sbuf_t *buffer, uint16_t padding)
{
    require(sbufGetTotalCapacityNoPadding(buffer) == MICRO_BUFFER_SIZE,
            "micro buffer lost its physical payload capacity");
    require(sbufGetLeftPadding(buffer) == padding && sbufGetLeftCapacity(buffer) == padding,
            "micro buffer has incorrect padding or cursor");
    require(sbufGetLength(buffer) == 0 && buffer->flags == 0 && sbufGetLifetime(buffer) == NULL,
            "micro checkout retained payload metadata");
}

static void testRechargeBatches(void)
{
    static const uint32_t widths[]              = {1, 2, 3, 4, 8, 256};
    sbuf_t *(*const getters[])(buffer_pool_t *) = {
        bufferpoolGetLargeBuffer, bufferpoolGetSmallBuffer, bufferpoolGetMicroBuffer};

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
    master_pool_t *micro = masterpoolCreateWithCapacity(16);
    require(large != NULL && small != NULL && micro != NULL, "failed to create test master pools");
    require(bufferpoolCreate(large, small, NULL, 2, 4096, 512) == NULL, "missing micro master was accepted");

#ifdef WW_MICRO_POOL_FAILURE_TEST
    const MasterPoolItemCreateHandle original_large = large->create_item_handle;
    const MasterPoolItemCreateHandle original_small = small->create_item_handle;
    const MasterPoolItemCreateHandle original_micro = micro->create_item_handle;
    for (unsigned int allocation = 1; allocation <= 4; ++allocation)
    {
        fail_allocation = allocation;
        require(bufferpoolCreate(large, small, micro, 2, 4096, 512) == NULL,
                "buffer pool metadata allocation failure was not returned");
        require(fail_allocation == 0, "metadata allocation failure was not exercised");
        require(large->create_item_handle == original_large && small->create_item_handle == original_small &&
                    micro->create_item_handle == original_micro,
                "failed construction published master callbacks");
    }
#endif

    buffer_pool_t *pool = bufferpoolCreate(large, small, micro, 2, 4096, 512);
    require(pool != NULL, "failed to create micro test pool");
    bufferpoolUpdateAllocationPaddings(pool, 64, 64, 33);
    require(bufferpoolGetMicroBufferSize(pool) == 32 && bufferpoolGetMicroBufferPadding(pool) == 64,
            "micro tier getters reported incorrect geometry");
    require(cachedMicroCount(pool) == 0, "micro cache was eagerly populated");

    sbuf_t *buffers[10];
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        buffers[i] = bufferpoolGetMicroBuffer(pool);
        checkMicro(buffers[i], 64);
    }
    buffers[0]->flags    = kSbufFlagSplice;
    buffers[0]->capacity = 64 + 8192;
    buffers[0]->len      = 8192;
    sbufShiftLeft(buffers[0], 4);
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        bufferpoolReuseBuffer(pool, buffers[i]);
    }
    require(cachedMicroCount(pool) <= 4 && atomicLoadRelaxed(&micro->len) > 0,
            "micro cache did not shrink to its shared master");
    require(cachedMicroCount(pool) + atomicLoadRelaxed(&micro->len) == ARRAY_SIZE(buffers),
            "recycling lost a micro buffer with virtual splice capacity");
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        buffers[i] = bufferpoolGetMicroBuffer(pool);
        checkMicro(buffers[i], 64);
    }
    for (size_t i = 0; i < ARRAY_SIZE(buffers); ++i)
    {
        bufferpoolReuseBuffer(pool, buffers[i]);
    }

    // A second pool can draw from the shared master while requiring different headroom.
    buffer_pool_t *other = bufferpoolCreate(large, small, micro, 1, 4096, 512);
    require(other != NULL, "failed to create the second micro pool");
    bufferpoolUpdateAllocationPaddings(other, 64, 64, 96);
    sbuf_t *buffer = bufferpoolGetMicroBuffer(other);
    checkMicro(buffer, 96);
    sbufSetLength(buffer, 32);
    memorySet(sbufGetMutablePtr(buffer), 0xA5, 32);
    sbuf_t *duplicate = sbufDuplicateByPool(other, buffer);
    require(sbufGetTotalCapacityNoPadding(duplicate) == 32 && sbufGetLeftPadding(duplicate) == 96 &&
                sbufGetLength(duplicate) == 32 && memoryEqual(sbufGetRawPtr(buffer), sbufGetRawPtr(duplicate), 32),
            "ordinary micro duplication changed payload or tier");
    bufferpoolReuseBuffer(other, duplicate);
    bufferpoolReuseBuffer(other, buffer);

    bufferpoolDestroy(other);
    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large);
    masterpoolMakeEmpty(small);
    masterpoolMakeEmpty(micro);
    masterpoolDestroy(large);
    masterpoolDestroy(small);
    masterpoolDestroy(micro);
    return 0;
}
