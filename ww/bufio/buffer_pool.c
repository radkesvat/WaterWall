/*
 * Implements buffer pool allocation, reuse, and adaptive recharge/shrink logic.
 */

#include "buffer_pool.h"
#include "buffer_pool_internal.h"
#include "loggers/internal_logger.h"
#include "shiftbuffer.h"
#include "wmath.h"

struct buffer_pool_s
{

    uint32_t cap;
    uint32_t free_threshold;
    uint32_t large_buffers_container_len;
    uint32_t large_buffers_size;
    uint16_t large_buffer_left_padding;

    uint32_t small_buffers_container_len;
    uint32_t small_buffers_size;
    uint16_t small_buffer_left_padding;

#if BUFFER_POOL_DEBUG == 1
    atomic_size_t in_use;
#endif

#if POOL_THREAD_CHECK
    tid_t tid;
#endif

    master_pool_t *large_buffers_mp;
    sbuf_t       **large_buffers;
    master_pool_t *small_buffers_mp;
    sbuf_t       **small_buffers;
};

/**
 * Checks if the current thread has access to the pool.
 * This has no effect on non-debug builds.
 * @param pool The generic pool to check access for.
 */
#if POOL_THREAD_CHECK
static inline void bufferpoolDebugCheckThreadAccess(buffer_pool_t *pool)
{
    if (UNLIKELY(pool->tid == 0))
    {
        // This is the first access, set the thread ID
        pool->tid = getTID();
    }
    if (UNLIKELY(pool->tid != getTID()))
    {
        printError("BufferPool: Access from wrong thread %d, expected %d", getTID(), pool->tid);
        abortProgramNow(1);
    }
}
#else
#define bufferpoolDebugCheckThreadAccess(pool) ((void) 0)
#endif

uint32_t bufferpoolGetLargeBufferSize(buffer_pool_t *pool)
{
    return pool->large_buffers_size;
}

uint16_t bufferpoolGetLargeBufferPadding(buffer_pool_t *pool)
{
    return pool->large_buffer_left_padding;
}

uint32_t bufferpoolGetSmallBufferSize(buffer_pool_t *pool)
{
    return pool->small_buffers_size;
}

uint16_t bufferpoolGetSmallBufferPadding(buffer_pool_t *pool)
{
    return pool->small_buffer_left_padding;
}

/**
 * Creates a large buffer using the provided create handler.
 * @param pool The master pool.
 * @param userdata User data passed to the create handler.
 * @return A pointer to the created large buffer.
 */
static master_pool_item_t *createLargeBufHandle(void *userdata)
{
    buffer_pool_t *bpool = userdata;
    return sbufCreateWithPadding(bpool->large_buffers_size, bpool->large_buffer_left_padding);
}

/**
 * Creates a small buffer using the provided create handler.
 * @param pool The master pool.
 * @param userdata User data passed to the create handler.
 * @return A pointer to the created small buffer.
 */
static master_pool_item_t *createSmallBufHandle(void *userdata)
{
    buffer_pool_t *bpool = userdata;
    return sbufCreateWithPadding(bpool->small_buffers_size, bpool->small_buffer_left_padding);
}

/**
 * Destroys a large buffer using the provided destroy handler.
 * @param pool The master pool.
 * @param item The large buffer to destroy.
 * @param userdata User data passed to the destroy handler.
 */
static void destroyLargeBufHandle(master_pool_item_t *item)
{
    sbufDestroy(item);
}

/**
 * Destroys a small buffer using the provided destroy handler.
 * @param pool The master pool.
 * @param item The small buffer to destroy.
 * @param userdata User data passed to the destroy handler.
 */
static void destroySmallBufHandle(master_pool_item_t *item)
{
    sbufDestroy(item);
}

static bool bufferMatchesGeometry(const sbuf_t *buf, uint32_t payload_capacity, uint16_t left_padding)
{
    return sbufGetTotalCapacityNoPadding((sbuf_t *) buf) == payload_capacity && sbufGetLeftPadding(buf) == left_padding;
}

static bool bufferpoolTiersHaveIdenticalGeometry(const buffer_pool_t *pool)
{
    return pool->large_buffers_size == pool->small_buffers_size &&
           pool->large_buffer_left_padding == pool->small_buffer_left_padding;
}

static sbuf_t *requireExactMasterBuffer(buffer_pool_t *pool, master_pool_t *master, sbuf_t *buf,
                                        uint32_t payload_capacity, uint16_t left_padding,
                                        MasterPoolItemCreateHandle create_handle)
{
    if (LIKELY(bufferMatchesGeometry(buf, payload_capacity, left_padding)))
    {
        return buf;
    }

    sbufDestroy(buf);
    return (sbuf_t *) masterpoolRequireCreatedItem(master, create_handle(pool), pool);
}

/**
 * Recharges the large buffers in the buffer pool by preallocating a number of buffers.
 * @param pool The buffer pool.
 */
static void reChargeLargeBuffers(buffer_pool_t *pool)
{
    const uint32_t increase = min((pool->cap - pool->large_buffers_container_len), pool->cap / 2);

    masterpoolGetItems(
        pool->large_buffers_mp, (void **) &(pool->large_buffers[pool->large_buffers_container_len]), increase, pool);

    for (uint32_t i = 0; i < increase; ++i)
    {
        const uint32_t index       = pool->large_buffers_container_len + i;
        pool->large_buffers[index] = requireExactMasterBuffer(pool,
                                                              pool->large_buffers_mp,
                                                              pool->large_buffers[index],
                                                              pool->large_buffers_size,
                                                              pool->large_buffer_left_padding,
                                                              createLargeBufHandle);
    }

    pool->large_buffers_container_len += increase;
#if BUFFER_POOL_DEBUG == 1
    LOGD("BufferPool: allocated %d new large buffers, %zu are in use", increase, pool->in_use);
#endif
}

/**
 * Recharges the small buffers in the buffer pool by preallocating a number of buffers.
 * @param pool The buffer pool.
 */
static void reChargeSmallBuffers(buffer_pool_t *pool)
{
    const uint32_t increase = min((pool->cap - pool->small_buffers_container_len), pool->cap / 2);

    masterpoolGetItems(
        pool->small_buffers_mp, (void **) &(pool->small_buffers[pool->small_buffers_container_len]), increase, pool);

    for (uint32_t i = 0; i < increase; ++i)
    {
        const uint32_t index       = pool->small_buffers_container_len + i;
        pool->small_buffers[index] = requireExactMasterBuffer(pool,
                                                              pool->small_buffers_mp,
                                                              pool->small_buffers[index],
                                                              pool->small_buffers_size,
                                                              pool->small_buffer_left_padding,
                                                              createSmallBufHandle);
    }

    pool->small_buffers_container_len += increase;
#if BUFFER_POOL_DEBUG == 1
    LOGD("BufferPool: allocated %d new small buffers, %zu are in use", increase, pool->in_use);
#endif
}

/**
 * Performs the initial charge of the buffer pool.
 * @param pool The buffer pool.
 */
static void firstCharge(buffer_pool_t *pool)
{
    if (pool->large_buffers_mp)
    {
        reChargeLargeBuffers(pool);
    }
    if (pool->small_buffers_mp)
    {
        reChargeSmallBuffers(pool);
    }
}

/**
 * Shrinks the large buffers in the buffer pool by releasing a number of buffers.
 * @param pool The buffer pool.
 */
static void shrinkLargeBuffers(buffer_pool_t *pool)
{
    const uint32_t decrease = min(pool->large_buffers_container_len, pool->cap / 2);

    masterpoolReuseItems(pool->large_buffers_mp,
                         (void **) &(pool->large_buffers[pool->large_buffers_container_len - decrease]),
                         decrease);

    pool->large_buffers_container_len -= decrease;

#if BUFFER_POOL_DEBUG == 1
    LOGD("BufferPool: freed %d large buffers, %zu are in use", decrease, pool->in_use);
#endif
}

/**
 * Shrinks the small buffers in the buffer pool by releasing a number of buffers.
 * @param pool The buffer pool.
 */
static void shrinkSmallBuffers(buffer_pool_t *pool)
{
    const uint32_t decrease = min(pool->small_buffers_container_len, pool->cap / 2);

    masterpoolReuseItems(pool->small_buffers_mp,
                         (void **) &(pool->small_buffers[pool->small_buffers_container_len - decrease]),
                         decrease);

    pool->small_buffers_container_len -= decrease;

#if BUFFER_POOL_DEBUG == 1
    LOGD("BufferPool: freed %d small buffers, %zu are in use", decrease, pool->in_use);
#endif
}

sbuf_t *bufferpoolGetLargeBuffer(buffer_pool_t *pool)
{
#if BYPASS_BUFFERPOOL == 1
    return masterpoolRequireCreatedItem(
        pool->large_buffers_mp, sbufCreateWithPadding(pool->large_buffers_size, pool->large_buffer_left_padding), pool);
#endif

#if BUFFER_POOL_DEBUG == 1
    pool->in_use += 1;
#endif

    bufferpoolDebugCheckThreadAccess(pool);

    if (LIKELY(pool->large_buffers_container_len > 0))
    {
        --(pool->large_buffers_container_len);
        return pool->large_buffers[pool->large_buffers_container_len];
    }
    if (bufferpoolTiersHaveIdenticalGeometry(pool) && pool->small_buffers_container_len > 0)
    {
        --(pool->small_buffers_container_len);
        return pool->small_buffers[pool->small_buffers_container_len];
    }
    reChargeLargeBuffers(pool);

    --(pool->large_buffers_container_len);
    return pool->large_buffers[pool->large_buffers_container_len];
}

sbuf_t *bufferpoolGetSmallBuffer(buffer_pool_t *pool)
{
#if BYPASS_BUFFERPOOL == 1
    return masterpoolRequireCreatedItem(
        pool->small_buffers_mp, sbufCreateWithPadding(pool->small_buffers_size, pool->small_buffer_left_padding), pool);
#endif

#if BUFFER_POOL_DEBUG == 1
    pool->in_use += 1;
#endif

    bufferpoolDebugCheckThreadAccess(pool);

    if (LIKELY(pool->small_buffers_container_len > 0))
    {
        --(pool->small_buffers_container_len);
        return pool->small_buffers[pool->small_buffers_container_len];
    }
    if (bufferpoolTiersHaveIdenticalGeometry(pool) && pool->large_buffers_container_len > 0)
    {
        --(pool->large_buffers_container_len);
        return pool->large_buffers[pool->large_buffers_container_len];
    }
    reChargeSmallBuffers(pool);

    --(pool->small_buffers_container_len);
    return pool->small_buffers[pool->small_buffers_container_len];
}

sbuf_t *bufferpoolGetBestFit(buffer_pool_t *pool, uint32_t minimum_payload, uint16_t minimum_left_padding)
{
    assert(pool != NULL);

    if (minimum_payload <= pool->small_buffers_size && minimum_left_padding <= pool->small_buffer_left_padding)
    {
        return bufferpoolGetSmallBuffer(pool);
    }

    if (minimum_payload <= pool->large_buffers_size && minimum_left_padding <= pool->large_buffer_left_padding)
    {
        return bufferpoolGetLargeBuffer(pool);
    }

    bufferpoolDebugCheckThreadAccess(pool);
#if BUFFER_POOL_DEBUG == 1 && BYPASS_BUFFERPOOL != 1
    pool->in_use += 1;
#endif
    return sbufCreateWithPadding(minimum_payload, minimum_left_padding);
}

void bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *b)
{

    assert(pool != NULL && b != NULL);
    bufferpoolDebugCheckThreadAccess(pool);

    if (UNLIKELY(b->is_temporary))
    {
        return;
    }

#if BYPASS_BUFFERPOOL == 1
    sbufDestroy(b);
    return;
#endif

#if BUFFER_POOL_DEBUG == 1
    pool->in_use -= 1;
#endif
    sbufReset(b);
    // we dont compare total capacity because another buffer can have 0 padding and more capacity but still
    // the sumation of capaicity and padding is the same, so we compare the capacity without padding and the padding
    // itself
    if (sbufGetTotalCapacityNoPadding(b) == pool->large_buffers_size &&
        sbufGetLeftPadding(b) == pool->large_buffer_left_padding)
    {
        if (UNLIKELY(pool->large_buffers_container_len > pool->free_threshold))
        {
            shrinkLargeBuffers(pool);
        }
        pool->large_buffers[(pool->large_buffers_container_len)++] = b;
    }
    else if (sbufGetTotalCapacityNoPadding(b) == pool->small_buffers_size &&
             sbufGetLeftPadding(b) == pool->small_buffer_left_padding)
    {
        if (UNLIKELY(pool->small_buffers_container_len > pool->free_threshold))
        {
            shrinkSmallBuffers(pool);
        }
        pool->small_buffers[(pool->small_buffers_container_len)++] = b;
    }
    else
    {
        sbufDestroy(b);
    }
}

void bufferpoolResetThreadOwnership(buffer_pool_t *pool)
{
    assert(pool != NULL);

#if POOL_THREAD_CHECK
    /*
     * This is deliberately a plain store: the API requires the former owner to
     * be joined and all other access to be quiesced before ownership moves.
     */
    pool->tid = 0;
#else
    discard pool;
#endif
}

sbuf_t *sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict b1, sbuf_t *restrict b2)
{
    b1 = sbufConcat(b1, b2);
    bufferpoolReuseBuffer(pool, b2);
    return b1;
}

sbuf_t *sbufDuplicateByPool(buffer_pool_t *pool, sbuf_t *b)
{
    const uint32_t source_length = sbufGetLength(b);
    sbuf_t        *bnew;
    if (sbufGetTotalCapacityNoPadding(b) == pool->large_buffers_size)
    {
        bnew = bufferpoolGetLargeBuffer(pool);
    }
    else if (sbufGetTotalCapacityNoPadding(b) == pool->small_buffers_size)
    {
        bnew = bufferpoolGetSmallBuffer(pool);
    }
    else
    {
        return sbufDuplicate(b);
    }

    if (UNLIKELY(source_length > sbufGetMaximumWriteableSize(bnew)))
    {
        bufferpoolReuseBuffer(pool, bnew);
        return sbufDuplicate(b);
    }

    sbufSetLength(bnew, source_length);
    sbufWriteBuf(bnew, b, source_length);
    sbufCloneLifetime(b, bnew);
    return bnew;
}

void bufferpoolUpdateAllocationPaddings(buffer_pool_t *pool, uint16_t large_buffer_left_padding,
                                        uint16_t small_buffer_left_padding)
{
    large_buffer_left_padding = sbufAlignLeftPadding(large_buffer_left_padding);
    small_buffer_left_padding = sbufAlignLeftPadding(small_buffer_left_padding);

    uint16_t l_new_max = max(pool->large_buffer_left_padding, large_buffer_left_padding);
    uint16_t s_new_max = max(pool->small_buffer_left_padding, small_buffer_left_padding);

    if (l_new_max == pool->large_buffer_left_padding && s_new_max == pool->small_buffer_left_padding)
    {
        return; // no change
    }
    assert(pool->small_buffers_container_len == 0 && pool->large_buffers_container_len == 0);

    pool->large_buffer_left_padding = l_new_max;
    pool->small_buffer_left_padding = s_new_max;
}

/*
 * Rounds a requested pool buffer size the same way sbufCreateWithPadding() will.
 *
 * This used to be open-coded here as a second copy of the cache-line round-up,
 * and that copy wrapped: a size within kCpuLineCacheSizeMin1 of UINT32_MAX
 * rounded to 0 and silently produced a pool of empty buffers. Every caller
 * currently passes a small constant, so it was not reachable, but a duplicate of
 * arithmetic that has already been wrong once does not need to stay.
 *
 * bufferpoolCreate() is nullable, so an unrepresentable geometry is rejected
 * transactionally before callbacks or metadata are published.
 */
static bool bufferpoolTryRoundBufferSize(uint32_t requested, uint32_t *rounded_out)
{
    uint32_t rounded = 0;
    if (! sbufTryComputeCapacity(requested, 0, &rounded))
    {
        return false;
    }
    *rounded_out = rounded;
    return true;
}

bool bufferpoolTryComputeGeometryForLimit(uint32_t pool_width, uint64_t allocation_limit, uint32_t *capacity_out,
                                          uint32_t *free_threshold_out, uint64_t *pointer_array_size_out)
{
    if (pool_width == 0 || capacity_out == NULL || free_threshold_out == NULL || pointer_array_size_out == NULL ||
        pool_width > UINT32_MAX / 2U)
    {
        return false;
    }

    const uint32_t capacity           = pool_width * 2U;
    const uint64_t pointer_array_size = (uint64_t) capacity * (uint64_t) sizeof(sbuf_t *);
    if ((uint64_t) sizeof(buffer_pool_t) > allocation_limit || pointer_array_size > allocation_limit)
    {
        return false;
    }

    /* floor(2 * capacity / 3), without the overflowing 32-bit multiply. */
    const uint32_t two_thirds = (capacity / 3U) * 2U + ((capacity % 3U) * 2U) / 3U;
    const uint32_t threshold  = max(capacity / 2U, two_thirds);

    *capacity_out           = capacity;
    *free_threshold_out     = threshold;
    *pointer_array_size_out = pointer_array_size;
    return true;
}

uint64_t bufferpoolMetadataSizeForTest(void)
{
    return (uint64_t) sizeof(buffer_pool_t);
}

void bufferpoolCachedTierCountsForTest(const buffer_pool_t *pool, uint32_t *large_count, uint32_t *small_count)
{
    assert(pool != NULL);
    assert(large_count != NULL);
    assert(small_count != NULL);
    *large_count = pool->large_buffers_container_len;
    *small_count = pool->small_buffers_container_len;
}

buffer_pool_t *bufferpoolCreate(master_pool_t *mp_large, master_pool_t *mp_small, uint32_t bufcount,
                                uint32_t large_buffer_size, uint32_t small_buffer_size)
{
    uint32_t capacity;
    uint32_t free_threshold;
    uint64_t container_len64;
    uint32_t rounded_large_buffer_size;
    uint32_t rounded_small_buffer_size;

    if (mp_large == NULL || mp_small == NULL ||
        ! bufferpoolTryComputeGeometryForLimit(bufcount, SIZE_MAX, &capacity, &free_threshold, &container_len64) ||
        ! bufferpoolTryRoundBufferSize(large_buffer_size, &rounded_large_buffer_size) ||
        ! bufferpoolTryRoundBufferSize(small_buffer_size, &rounded_small_buffer_size))
    {
        return NULL;
    }

    const size_t container_len = (size_t) container_len64;

#ifdef DEBUG
    sbuf_t *test_large_buf = sbufCreateWithPadding(rounded_large_buffer_size, 0);
    sbuf_t *test_small_buf = sbufCreateWithPadding(rounded_small_buffer_size, 0);
    if (test_large_buf == NULL || test_small_buf == NULL)
    {
        if (test_large_buf != NULL)
        {
            sbufDestroy(test_large_buf);
        }
        if (test_small_buf != NULL)
        {
            sbufDestroy(test_small_buf);
        }
        return NULL;
    }
    assert(sbufGetTotalCapacityNoPadding(test_large_buf) == rounded_large_buffer_size);
    assert(sbufGetLeftPadding(test_large_buf) == 0);
    assert(sbufGetTotalCapacityNoPadding(test_small_buf) == rounded_small_buffer_size);
    assert(sbufGetLeftPadding(test_small_buf) == 0);
    sbufDestroy(test_large_buf);
    sbufDestroy(test_small_buf);
#endif

    buffer_pool_t *ptr_pool = memoryAllocate(sizeof(buffer_pool_t));
    if (ptr_pool == NULL)
    {
        return NULL;
    }

    sbuf_t **large_buffers = (sbuf_t **) memoryAllocate(container_len);
    if (large_buffers == NULL)
    {
        memoryFree(ptr_pool);
        return NULL;
    }

    sbuf_t **small_buffers = (sbuf_t **) memoryAllocate(container_len);
    if (small_buffers == NULL)
    {
        memoryFree(large_buffers);
        memoryFree(ptr_pool);
        return NULL;
    }

    *ptr_pool = (buffer_pool_t) {
        .cap                = capacity,
        .large_buffers_size = rounded_large_buffer_size,
        .small_buffers_size = rounded_small_buffer_size,
        .free_threshold     = free_threshold,

#if BUFFER_POOL_DEBUG == 1
        .in_use = 0,
#endif

#if POOL_THREAD_CHECK
        .tid = 0,
#endif
        .large_buffers_mp = mp_large,
        .large_buffers    = large_buffers,
        .small_buffers_mp = mp_small,
        .small_buffers    = small_buffers,
    };

    masterpoolInstallCallBacks(ptr_pool->large_buffers_mp, createLargeBufHandle, destroyLargeBufHandle);
    masterpoolInstallCallBacks(ptr_pool->small_buffers_mp, createSmallBufHandle, destroySmallBufHandle);

#ifdef DEBUG
    memorySet((void *) ptr_pool->large_buffers, 0xFE, container_len);
    memorySet((void *) ptr_pool->small_buffers, 0xFE, container_len);
#endif

    // firstCharge(ptr_pool);
    return ptr_pool;
}

void bufferpoolDestroy(buffer_pool_t *pool)
{
    if (pool == NULL)
    {
        return;
    }
    for (uint32_t s_i = 0; s_i < pool->small_buffers_container_len; s_i++)
    {
        sbufDestroy(pool->small_buffers[s_i]);
    }
    for (uint32_t l_i = 0; l_i < pool->large_buffers_container_len; l_i++)
    {
        sbufDestroy(pool->large_buffers[l_i]);
    }
    memoryFree((void *) pool->large_buffers);
    memoryFree((void *) pool->small_buffers);
    memoryFree(pool);
}
