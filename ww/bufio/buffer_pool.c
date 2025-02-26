#include "buffer_pool.h"
#include "loggers/internal_logger.h"
#include "shiftbuffer.h"
#include "wplatform.h"


struct buffer_pool_s
{

    uint16_t cap;
    uint16_t free_threshold;
    uint32_t large_buffers_container_len;
    uint32_t large_buffers_size;
    uint16_t large_buffer_left_padding;

    uint32_t small_buffers_container_len;
    uint32_t small_buffers_size;
    uint16_t small_buffer_left_padding;

#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    atomic_size_t in_use;
#endif

    master_pool_t *large_buffers_mp;
    sbuf_t       **large_buffers;
    master_pool_t *small_buffers_mp;
    sbuf_t       **small_buffers;
};

/**
 * Gets the size of large buffers in the buffer pool.
 * @param pool The buffer pool.
 * @return The size of large buffers.
 */
uint32_t bufferpoolGetLargeBufferSize(buffer_pool_t *pool)
{
    return pool->large_buffers_size;
}

uint16_t bufferpoolGetLargeBufferPadding(buffer_pool_t *pool)
{
    return pool->large_buffer_left_padding;
}

/**
 * Gets the size of small buffers in the buffer pool.
 * @param pool The buffer pool.
 * @return The size of small buffers.
 */
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
static master_pool_item_t *createLargeBufHandle(master_pool_t *pool, void *userdata)
{
    (void) pool;

    buffer_pool_t *bpool = userdata;
    return sbufNewWithPadding(bpool->large_buffers_size, bpool->large_buffer_left_padding);
}

/**
 * Creates a small buffer using the provided create handler.
 * @param pool The master pool.
 * @param userdata User data passed to the create handler.
 * @return A pointer to the created small buffer.
 */
static master_pool_item_t *createSmallBufHandle(master_pool_t *pool, void *userdata)
{
    (void) pool;
    buffer_pool_t *bpool = userdata;
    return sbufNewWithPadding(bpool->small_buffers_size, bpool->small_buffer_left_padding);
}

/**
 * Destroys a large buffer using the provided destroy handler.
 * @param pool The master pool.
 * @param item The large buffer to destroy.
 * @param userdata User data passed to the destroy handler.
 */
static void destroyLargeBufHandle(master_pool_t *pool, master_pool_item_t *item, void *userdata)
{
    (void) pool;
    (void) userdata;
    sbufDestroy(item);
}

/**
 * Destroys a small buffer using the provided destroy handler.
 * @param pool The master pool.
 * @param item The small buffer to destroy.
 * @param userdata User data passed to the destroy handler.
 */
static void destroySmallBufHandle(master_pool_t *pool, master_pool_item_t *item, void *userdata)
{
    (void) pool;
    (void) userdata;
    sbufDestroy(item);
}

/**
 * Recharges the large buffers in the buffer pool by preallocating a number of buffers.
 * @param pool The buffer pool.
 */
static void reChargeLargeBuffers(buffer_pool_t *pool)
{
    const uint32_t increase = min((pool->cap - pool->large_buffers_container_len), pool->cap / 2);

    masterpoolGetItems(pool->large_buffers_mp,
                       (void const **) &(pool->large_buffers[pool->large_buffers_container_len]), increase, pool);

    pool->large_buffers_container_len += increase;
#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
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

    masterpoolGetItems(pool->small_buffers_mp,
                       (void const **) &(pool->small_buffers[pool->small_buffers_container_len]), increase, pool);

    pool->small_buffers_container_len += increase;
#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
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
                         (void **) &(pool->large_buffers[pool->large_buffers_container_len - decrease]), decrease,
                         pool);

    pool->large_buffers_container_len -= decrease;

#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
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
                         (void **) &(pool->small_buffers[pool->small_buffers_container_len - decrease]), decrease,
                         pool);

    pool->small_buffers_container_len -= decrease;

#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    LOGD("BufferPool: freed %d small buffers, %zu are in use", decrease, pool->in_use);
#endif
}

/**
 * Retrieves a large buffer from the buffer pool.
 * @param pool The buffer pool.
 * @return A pointer to the retrieved large buffer.
 */
sbuf_t *bufferpoolGetLargeBuffer(buffer_pool_t *pool)
{
#if defined(DEBUG) && defined(BYPASS_BUFFERPOOL)
    return sbufNewWithPadding(pool->large_buffers_size, pool->large_buffer_left_padding);
#endif
#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    pool->in_use += 1;
#endif

    if (LIKELY(pool->large_buffers_container_len > 0))
    {
        --(pool->large_buffers_container_len);
        return pool->large_buffers[pool->large_buffers_container_len];
    }
    reChargeLargeBuffers(pool);

    --(pool->large_buffers_container_len);
    return pool->large_buffers[pool->large_buffers_container_len];
}

/**
 * Retrieves a small buffer from the buffer pool.
 * @param pool The buffer pool.
 * @return A pointer to the retrieved small buffer.
 */
sbuf_t *bufferpoolGetSmallBuffer(buffer_pool_t *pool)
{
#if defined(DEBUG) && defined(BYPASS_BUFFERPOOL)
    return sbufNewWithPadding(pool->small_buffers_size, pool->small_buffer_left_padding);
#endif
#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    pool->in_use += 1;
#endif

    if (LIKELY(pool->small_buffers_container_len > 0))
    {
        --(pool->small_buffers_container_len);
        return pool->small_buffers[pool->small_buffers_container_len];
    }
    reChargeSmallBuffers(pool);

    --(pool->small_buffers_container_len);
    return pool->small_buffers[pool->small_buffers_container_len];
}

/**
 * Reuses a buffer by returning it to the buffer pool.
 * @param pool The buffer pool.
 * @param b The buffer to reuse.
 */
void bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *b)
{

#if defined(DEBUG) && defined(BYPASS_BUFFERPOOL)
    sbufDestroy(b);
    return;
#endif

#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    pool->in_use -= 1;
#endif

    if (sbufGetTotalCapacityNoPadding(b) == pool->large_buffers_size)
    {
        if (UNLIKELY(pool->large_buffers_container_len > pool->free_threshold))
        {
            shrinkLargeBuffers(pool);
        }
        pool->large_buffers[(pool->large_buffers_container_len)++] = b;
    }
    else if (sbufGetTotalCapacityNoPadding(b) == pool->small_buffers_size)
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

/**
 * Appends and merges two buffers.
 * @param pool The buffer pool.
 * @param b1 The first buffer.
 * @param b2 The second buffer.
 * @return A pointer to the merged buffer.
 */
sbuf_t *sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict b1, sbuf_t *restrict b2)
{
    b1 = sbufConcat(b1, b2);
    bufferpoolReuseBuffer(pool, b2);
    return b1;
}

/**
 * Duplicates a buffer using the buffer pool.
 * @param pool The buffer pool.
 * @param b The buffer to duplicate.
 * @return A pointer to the duplicated buffer.
 */
sbuf_t *sbufDuplicateByPool(buffer_pool_t *pool, sbuf_t *b)
{
    sbuf_t *bnew;
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
    sbufSetLength(bnew, sbufGetLength(b));
    sbufWriteBuf(bnew, b, sbufGetLength(b));
    return bnew;
}

/**
 * Updates the allocation paddings for the buffer pool.
 * @param pool The buffer pool.
 * @param large_buffer_left_padding The left padding for large buffers.
 * @param small_buffer_left_padding The left padding for small buffers.
 */
void bufferpoolUpdateAllocationPaddings(buffer_pool_t *pool, uint16_t large_buffer_left_padding,
                                        uint16_t small_buffer_left_padding)
{
    assert(pool->small_buffers_container_len == 0 && pool->large_buffers_container_len == 0);

    pool->large_buffer_left_padding = max(pool->large_buffer_left_padding, large_buffer_left_padding);
    pool->small_buffer_left_padding = max(pool->small_buffer_left_padding, small_buffer_left_padding);
}

/**
 * Creates a buffer pool with specified parameters.
 * @param mp_large The master pool for large buffers.
 * @param mp_small The master pool for small buffers.
 * @param bufcount The number of buffers to preallocate.
 * @param large_buffer_size The size of each large buffer.
 * @param small_buffer_size The size of each small buffer.
 * @return A pointer to the created buffer pool.
 */
buffer_pool_t *bufferpoolCreate(master_pool_t *mp_large, master_pool_t *mp_small, uint32_t bufcount,
                                uint32_t large_buffer_size, uint32_t small_buffer_size)
{
    // stop using pool if you want less, simply uncomment lines in popbuffer and bufferpoolReuseBuffer
    assert(bufcount >= 1);

    bufcount = 2 * bufcount;

    const unsigned long container_len = bufcount * sizeof(sbuf_t *);

    buffer_pool_t *ptr_pool = memoryAllocate(sizeof(buffer_pool_t));

    *ptr_pool = (buffer_pool_t)
    {
        .cap = (uint16_t) bufcount, .large_buffers_size = large_buffer_size, .small_buffers_size = small_buffer_size,
        .free_threshold = (uint16_t) max(bufcount / 2, (bufcount * 2) / 3),

#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
        .in_use = 0,
#endif

        .large_buffers_mp = mp_large, .large_buffers = (sbuf_t **) memoryAllocate(container_len),
        .small_buffers_mp = mp_small, .small_buffers = (sbuf_t **) memoryAllocate(container_len),
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
    memoryFree(pool->large_buffers);
    memoryFree(pool->small_buffers);
    memoryFree(pool);
}
