#include "buffer_pool.h"
#include "wplatform.h"
#ifdef DEBUG
#include "loggers/internal_logger.h"
#endif
#include "shiftbuffer.h"
#include "utils/mathutils.h"

#include "worker.h"
#include <assert.h> // for assert
#include <stdlib.h>
#include <string.h>

// #define BYPASS_BUFFERPOOL

#define MEMORY_PROFILE_SMALL    (RAM_PROFILE >= kRamProfileM1Memory ? kRamProfileM1Memory : RAM_PROFILE)
#define MEMORY_PROFILE_SELECTED RAM_PROFILE

#define SMALL_BUFFER_SIZE              1500
#define BUFFERPOOL_SMALL_CONTAINER_LEN ((unsigned long) ((MEMORY_PROFILE_SMALL)))
#define BUFFERPOOL_CONTAINER_LEN       ((unsigned long) ((MEMORY_PROFILE_SELECTED)))

#define LARGE_BUFFER_SIZE                                                                                              \
    (RAM_PROFILE >= kRamProfileS2Memory ? (1U << 15) : (1U << 12)) // 32k (same as nginx file streaming)

struct buffer_pool_s
{

    uint16_t cap;
    uint16_t free_threshold;

    uint32_t large_buffers_container_len;
    uint32_t large_buffers_default_size;
    uint16_t large_buffer_left_padding;
    uint16_t large_buffer_right_padding;

    uint32_t small_buffers_container_len;
    uint32_t small_buffers_default_size;
    uint16_t small_buffer_left_padding;
    uint16_t small_buffer_right_padding;

#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    atomic_size_t in_use;
#endif

    master_pool_t   *large_buffers_mp;
    shift_buffer_t **large_buffers;
    master_pool_t   *small_buffers_mp;
    shift_buffer_t **small_buffers;
};

uint32_t getBufferPoolLargeBufferDefaultSize(void)
{
    return LARGE_BUFFER_SIZE;
}

uint32_t getBufferPoolSmallBufferDefaultSize(void)
{
    return SMALL_BUFFER_SIZE;
}

static master_pool_item_t *createLargeBufHandle(struct master_pool_s *pool, void *userdata)
{
    (void) pool;

    buffer_pool_t *bpool = userdata;
    return newShiftBufferWithPad(bpool->large_buffers_default_size, bpool->large_buffer_left_padding,
                                 bpool->large_buffer_right_padding);
}

static master_pool_item_t *createSmallBufHandle(struct master_pool_s *pool, void *userdata)
{
    (void) pool;
    buffer_pool_t *bpool = userdata;
    return newShiftBufferWithPad(bpool->small_buffers_default_size, bpool->small_buffer_left_padding,
                                 bpool->small_buffer_right_padding);
}

static void destroyLargeBufHandle(struct master_pool_s *pool, master_pool_item_t *item, void *userdata)
{
    (void) pool;
    (void) userdata;
    destroyShiftBuffer(item);
}

static void destroySmallBufHandle(struct master_pool_s *pool, master_pool_item_t *item, void *userdata)
{
    (void) pool;
    (void) userdata;
    destroyShiftBuffer(item);
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

shift_buffer_t *popBuffer(buffer_pool_t *pool)
{
#if defined(DEBUG) && defined(BYPASS_BUFFERPOOL)
    return newShiftBufferWithPad(pool->large_buffers_default_size, pool->large_buffer_left_padding,
                                 pool->large_buffer_right_padding);
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

shift_buffer_t *popSmallBuffer(buffer_pool_t *pool)
{
#if defined(DEBUG) && defined(BYPASS_BUFFERPOOL)
    return newShiftBufferWithPad(pool->small_buffers_default_size, pool->small_buffer_left_padding,
                                 pool->small_buffer_right_padding);
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

void reuseBuffer(buffer_pool_t *pool, shift_buffer_t *b)
{

#if defined(DEBUG) && defined(BYPASS_BUFFERPOOL)
    destroyShiftBuffer(b);
    return;
#endif

#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    pool->in_use -= 1;
#endif

    if (bufCapNoPadding(b) == pool->large_buffers_default_size)
    {
        if (UNLIKELY(pool->large_buffers_container_len > pool->free_threshold))
        {
            shrinkLargeBuffers(pool);
        }
        pool->large_buffers[(pool->large_buffers_container_len)++] = b;
    }
    else if (bufCapNoPadding(b) == pool->small_buffers_default_size)
    {
        if (UNLIKELY(pool->small_buffers_container_len > pool->free_threshold))
        {
            shrinkSmallBuffers(pool);
        }
        pool->small_buffers[(pool->small_buffers_container_len)++] = b;
    }
    else
    {
        destroyShiftBuffer(b);
    }
}

shift_buffer_t *appendBufferMerge(buffer_pool_t *pool, shift_buffer_t *restrict b1, shift_buffer_t *restrict b2)
{
    b1 = concatBuffer(b1, b2);
    reuseBuffer(pool, b2);
    return b1;
}

shift_buffer_t *duplicateBufferP(buffer_pool_t *pool, shift_buffer_t *b)
{
    shift_buffer_t *bnew;
    if (bufCapNoPadding(b) == pool->large_buffers_default_size)
    {
        bnew = popBuffer(pool);
    }
    else if (bufCapNoPadding(b) == pool->small_buffers_default_size)
    {
        bnew = popSmallBuffer(pool);
    }
    else
    {
        return duplicateBuffer(b);
    }
    setLen(bnew, bufLen(b));
    copyBuf(bnew, b, bufLen(b));
    return bnew;
}

void updateBufferPooleAllocationPaddings(buffer_pool_t *pool, uint16_t large_buffer_left_padding,
                                        uint16_t large_buffer_right_padding, uint16_t small_buffer_left_padding,
                                        uint16_t small_buffer_right_padding)
{
    assert(pool->small_buffers_container_len == 0 && pool->large_buffers_container_len == 0);
    

    pool->large_buffer_left_padding  = max(pool->large_buffer_left_padding,large_buffer_left_padding);
    pool->large_buffer_right_padding = max(pool->large_buffer_right_padding,large_buffer_right_padding);
    pool->small_buffer_left_padding  = max(pool->small_buffer_left_padding,small_buffer_left_padding);
    pool->small_buffer_right_padding = max(pool->small_buffer_right_padding,small_buffer_right_padding);
}

static buffer_pool_t *allocBufferPool(struct master_pool_s *mp_large, struct master_pool_s *mp_small, uint32_t bufcount,
                                      uint32_t large_buffer_size, uint32_t small_buffer_size)
{
    // stop using pool if you want less, simply uncomment lines in popbuffer and reuseBuffer
    assert(bufcount >= 1);

    // half of the pool is used, other half is free at startup
    bufcount = 2 * bufcount;

    const unsigned long container_len = bufcount * sizeof(shift_buffer_t *);

    buffer_pool_t *ptr_pool = memoryAllocate(sizeof(buffer_pool_t));

    *ptr_pool = (buffer_pool_t) {
        .cap                        = bufcount,
        .large_buffers_default_size = large_buffer_size,
        .small_buffers_default_size = small_buffer_size,
        .free_threshold             = max(bufcount / 2, (bufcount * 2) / 3),
#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
        .in_use = 0,
#endif
        .large_buffers_mp = mp_large,
        .large_buffers    = (shift_buffer_t **) memoryAllocate(container_len),
        .small_buffers_mp = mp_small,
        .small_buffers    = (shift_buffer_t **) memoryAllocate(container_len),
    };

    installMasterPoolAllocCallbacks(ptr_pool->large_buffers_mp, createLargeBufHandle, destroyLargeBufHandle);
    installMasterPoolAllocCallbacks(ptr_pool->small_buffers_mp, createSmallBufHandle, destroySmallBufHandle);

#ifdef DEBUG
    memorySet((void *) ptr_pool->large_buffers, 0xFE, container_len);
    memorySet((void *) ptr_pool->small_buffers, 0xFE, container_len);
#endif

    // firstCharge(ptr_pool);
    return ptr_pool;
}

buffer_pool_t *createBufferPool(struct master_pool_s *mp_large, struct master_pool_s *mp_small, uint32_t pool_width)
{
    return allocBufferPool(mp_large, mp_small, pool_width, LARGE_BUFFER_SIZE, SMALL_BUFFER_SIZE);
}
