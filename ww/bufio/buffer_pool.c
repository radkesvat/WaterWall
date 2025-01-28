#include "buffer_pool.h"
#include "wplatform.h"
#include "loggers/internal_logger.h"
#include "shiftbuffer.h"

buffer_pool_t
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

uint32_t bufferpoolGetLargeBufferSize(buffer_pool_t *pool)
{
    return pool->large_buffers_size;
}

uint32_t bufferpoolGetSmallBufferSize(buffer_pool_t *pool)
{
    return pool->small_buffers_size;
}

static master_pool_item_t *createLargeBufHandle(struct master_pool_s *pool, void *userdata)
{
    (void) pool;

    buffer_pool_t *bpool = userdata;
    return sbufNewWithPadding(bpool->large_buffers_size, bpool->large_buffer_left_padding);
}

static master_pool_item_t *createSmallBufHandle(struct master_pool_s *pool, void *userdata)
{
    (void) pool;
    buffer_pool_t *bpool = userdata;
    return sbufNewWithPadding(bpool->small_buffers_size, bpool->small_buffer_left_padding);
}

static void destroyLargeBufHandle(struct master_pool_s *pool, master_pool_item_t *item, void *userdata)
{
    (void) pool;
    (void) userdata;
    sbufDestroy(item);
}

static void destroySmallBufHandle(struct master_pool_s *pool, master_pool_item_t *item, void *userdata)
{
    (void) pool;
    (void) userdata;
    sbufDestroy(item);
}

static void reChargeLargeBuffers(buffer_pool_t *pool)
{
    const size_t increase = min((pool->cap - pool->large_buffers_container_len), pool->cap / 2);

    popMasterPoolItems(pool->large_buffers_mp,
                       (void const **) &(pool->large_buffers[pool->large_buffers_container_len]), increase, pool);

    pool->large_buffers_container_len += increase;
#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    LOGD("BufferPool: allocated %d new large buffers, %zu are in use", increase, pool->in_use);
#endif
}

static void reChargeSmallBuffers(buffer_pool_t *pool)
{
    const size_t increase = min((pool->cap - pool->small_buffers_container_len), pool->cap / 2);

    popMasterPoolItems(pool->small_buffers_mp,
                       (void const **) &(pool->small_buffers[pool->small_buffers_container_len]), increase, pool);

    pool->small_buffers_container_len += increase;
#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    LOGD("BufferPool: allocated %d new small buffers, %zu are in use", increase, pool->in_use);
#endif
}

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

static void shrinkLargeBuffers(buffer_pool_t *pool)
{
    const size_t decrease = min(pool->large_buffers_container_len, pool->cap / 2);

    reuseMasterPoolItems(pool->large_buffers_mp,
                         (void **) &(pool->large_buffers[pool->large_buffers_container_len - decrease]), decrease,
                         pool);

    pool->large_buffers_container_len -= decrease;

#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    LOGD("BufferPool: freed %d large buffers, %zu are in use", decrease, pool->in_use);
#endif
}

static void shrinkSmallBuffers(buffer_pool_t *pool)
{
    const size_t decrease = min(pool->small_buffers_container_len, pool->cap / 2);

    reuseMasterPoolItems(pool->small_buffers_mp,
                         (void **) &(pool->small_buffers[pool->small_buffers_container_len - decrease]), decrease,
                         pool);

    pool->small_buffers_container_len -= decrease;

#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    LOGD("BufferPool: freed %d small buffers, %zu are in use", decrease, pool->in_use);
#endif
}

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

void bufferpoolResuesBuffer(buffer_pool_t *pool, sbuf_t *b)
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

sbuf_t *sbufAppendMerge(buffer_pool_t *pool, sbuf_t *restrict b1, sbuf_t *restrict b2)
{
    b1 = sbufConcat(b1, b2);
    bufferpoolResuesBuffer(pool, b2);
    return b1;
}

sbuf_t *sbufAppendMergeNoPadding(buffer_pool_t *pool, sbuf_t *restrict b1, sbuf_t *restrict b2)
{
    b1 = sbufConcat(b1, b2);
    bufferpoolResuesBuffer(pool, b2);
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
    sbufSetLength(bnew, sbufGetBufLength(b));
    sbufWriteBuf(bnew, b, sbufGetBufLength(b));
    return bnew;
}

void bufferpoolUpdateAllocationPaddings(buffer_pool_t *pool, uint16_t large_buffer_left_padding,
                                        uint16_t small_buffer_left_padding)
{
    assert(pool->small_buffers_container_len == 0 && pool->large_buffers_container_len == 0);

    pool->large_buffer_left_padding = max(pool->large_buffer_left_padding, large_buffer_left_padding);
    pool->small_buffer_left_padding = max(pool->small_buffer_left_padding, small_buffer_left_padding);
}

buffer_pool_t *bufferpoolCreate(struct master_pool_s *mp_large, struct master_pool_s *mp_small, uint32_t bufcount,
                                uint32_t large_buffer_size, uint32_t small_buffer_size)
{
    // stop using pool if you want less, simply uncomment lines in popbuffer and bufferpoolResuesBuffer
    assert(bufcount >= 1);

    bufcount = 2 * bufcount;

    const unsigned long container_len = bufcount * sizeof(sbuf_t *);

    buffer_pool_t *ptr_pool = memoryAllocate(sizeof(buffer_pool_t));

    *ptr_pool = (buffer_pool_t)
    {
        .cap = bufcount, .large_buffers_size = large_buffer_size,
        .small_buffers_size = small_buffer_size, .free_threshold = max(bufcount / 2, (bufcount * 2) / 3),

#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
        .in_use = 0,
#endif

        .large_buffers_mp = mp_large, .large_buffers = (sbuf_t **) memoryAllocate(container_len),
        .small_buffers_mp = mp_small, .small_buffers = (sbuf_t **) memoryAllocate(container_len),
    };

    installMasterPoolAllocCallBacks(ptr_pool->large_buffers_mp, createLargeBufHandle, destroyLargeBufHandle);
    installMasterPoolAllocCallBacks(ptr_pool->small_buffers_mp, createSmallBufHandle, destroySmallBufHandle);

#ifdef DEBUG
    memorySet((void *) ptr_pool->large_buffers, 0xFE, container_len);
    memorySet((void *) ptr_pool->small_buffers, 0xFE, container_len);
#endif

    // firstCharge(ptr_pool);
    return ptr_pool;
}
