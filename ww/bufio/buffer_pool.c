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

#if BUFFER_POOL_DEBUG == 1
    atomic_size_t in_use;
#endif

#ifdef DEBUG
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
#ifdef DEBUG
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
        terminateProgram(1);
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
static master_pool_item_t *createLargeBufHandle(master_pool_t *pool, void *userdata)
{
    discard pool;

    buffer_pool_t *bpool = userdata;
    return sbufCreateWithPadding(bpool->large_buffers_size, bpool->large_buffer_left_padding);
}

/**
 * Creates a small buffer using the provided create handler.
 * @param pool The master pool.
 * @param userdata User data passed to the create handler.
 * @return A pointer to the created small buffer.
 */
static master_pool_item_t *createSmallBufHandle(master_pool_t *pool, void *userdata)
{
    discard        pool;
    buffer_pool_t *bpool = userdata;
    return sbufCreateWithPadding(bpool->small_buffers_size, bpool->small_buffer_left_padding);
}

/**
 * Destroys a large buffer using the provided destroy handler.
 * @param pool The master pool.
 * @param item The large buffer to destroy.
 * @param userdata User data passed to the destroy handler.
 */
static void destroyLargeBufHandle(master_pool_t *pool, master_pool_item_t *item, void *userdata)
{
    discard pool;
    discard userdata;
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
    discard pool;
    discard userdata;
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

    masterpoolGetItems(pool->small_buffers_mp,
                       (void const **) &(pool->small_buffers[pool->small_buffers_container_len]), increase, pool);

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
                         (void **) &(pool->large_buffers[pool->large_buffers_container_len - decrease]), decrease,
                         pool);

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
                         (void **) &(pool->small_buffers[pool->small_buffers_container_len - decrease]), decrease,
                         pool);

    pool->small_buffers_container_len -= decrease;

#if BUFFER_POOL_DEBUG == 1
    LOGD("BufferPool: freed %d small buffers, %zu are in use", decrease, pool->in_use);
#endif
}

sbuf_t *bufferpoolGetLargeBuffer(buffer_pool_t *pool)
{
#if BYPASS_BUFFERPOOL == 1
    return sbufCreateWithPadding(pool->large_buffers_size, pool->large_buffer_left_padding);
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
    reChargeLargeBuffers(pool);

    --(pool->large_buffers_container_len);
    return pool->large_buffers[pool->large_buffers_container_len];
}

sbuf_t *bufferpoolGetSmallBuffer(buffer_pool_t *pool)
{
#if BYPASS_BUFFERPOOL == 1
    return sbufCreateWithPadding(pool->small_buffers_size, pool->small_buffer_left_padding);
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

    if (sbufGetTotalCapacityNoPadding(b) == pool->large_buffers_size && sbufGetLeftPadding(b) == pool->large_buffer_left_padding)
    {
        if (UNLIKELY(pool->large_buffers_container_len > pool->free_threshold))
        {
            shrinkLargeBuffers(pool);
        }
        pool->large_buffers[(pool->large_buffers_container_len)++] = b;
    }
    else if (sbufGetTotalCapacityNoPadding(b) == pool->small_buffers_size && sbufGetLeftPadding(b) == pool->small_buffer_left_padding)
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

sbuf_t *sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict b1, sbuf_t *restrict b2)
{
    b1 = sbufConcat(b1, b2);
    bufferpoolReuseBuffer(pool, b2);
    return b1;
}

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

void bufferpoolUpdateAllocationPaddings(buffer_pool_t *pool, uint16_t large_buffer_left_padding,
                                        uint16_t small_buffer_left_padding)
{

    uint16_t l_new_max = max(pool->large_buffer_left_padding, large_buffer_left_padding);
    uint16_t s_new_max = max(pool->small_buffer_left_padding, small_buffer_left_padding);

    if(l_new_max == pool->large_buffer_left_padding &&
        s_new_max == pool->small_buffer_left_padding)
    {
        return; // no change
    }
    assert(pool->small_buffers_container_len == 0 && pool->large_buffers_container_len == 0);

    pool->large_buffer_left_padding = l_new_max;
    pool->small_buffer_left_padding = s_new_max;
}

buffer_pool_t *bufferpoolCreate(master_pool_t *mp_large, master_pool_t *mp_small, uint32_t bufcount,
                                uint32_t large_buffer_size, uint32_t small_buffer_size)
{
    // stop using pool if you want less, simply uncomment lines in popbuffer and bufferpoolReuseBuffer
    assert(bufcount >= 1);

    bufcount = 2 * bufcount;

    const unsigned long container_len = bufcount * sizeof(sbuf_t *);

    buffer_pool_t *ptr_pool = memoryAllocate(sizeof(buffer_pool_t));

    *ptr_pool = (buffer_pool_t) {
        .cap                = (uint16_t) bufcount,
        .large_buffers_size = large_buffer_size,
        .small_buffers_size = small_buffer_size,
        .free_threshold     = (uint16_t) max(bufcount / 2, (bufcount * 2) / 3),

#if BUFFER_POOL_DEBUG == 1
        .in_use = 0,
#endif

#ifdef DEBUG
        .tid = 0,
#endif
        .large_buffers_mp = mp_large,
        .large_buffers    = (sbuf_t **) memoryAllocate(container_len),
        .small_buffers_mp = mp_small,
        .small_buffers    = (sbuf_t **) memoryAllocate(container_len),
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
    for (uint32_t s_i = 0; s_i < pool->small_buffers_container_len; s_i++)
    {
        sbufDestroy(pool->small_buffers[s_i]);
    }
    for (uint32_t l_i = 0; l_i < pool->large_buffers_container_len; l_i++)
    {
        sbufDestroy(pool->large_buffers[l_i]);
    }
    masterpoolMakeEmpty(pool->large_buffers_mp, pool);
    masterpoolMakeEmpty(pool->small_buffers_mp, pool);
    memoryFree((void *) pool->large_buffers);
    memoryFree((void *) pool->small_buffers);
    memoryFree(pool);
}
