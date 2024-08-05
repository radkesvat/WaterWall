#include "buffer_pool.h"
#include "hplatform.h"
#ifdef DEBUG
#include "loggers/network_logger.h"
#endif
#include "shiftbuffer.h"
#include "utils/mathutils.h"
#include "ww.h"
#include <assert.h> // for assert
#include <stdlib.h>
#include <string.h>
// #define BYPASS_BUFFERPOOL

// NOLINTBEGIN

#define MEMORY_PROFILE_SMALL    (RAM_PROFILE >= kRamProfileM1Memory ? kRamProfileM1Memory : RAM_PROFILE)
#define MEMORY_PROFILE_SELECTED RAM_PROFILE

#define SMALL_BUFSIZE                  1500
#define BUFFERPOOL_SMALL_CONTAINER_LEN ((unsigned long) ((MEMORY_PROFILE_SMALL)))
#define BUFFERPOOL_CONTAINER_LEN       ((unsigned long) ((MEMORY_PROFILE_SELECTED)))

#define BUFFER_SIZE (RAM_PROFILE >= kRamProfileS2Memory ? (1U << 15) : (1U << 12)) // 32k (same as nginx file streaming)

struct buffer_pool_s
{

    uint16_t               cap;
    uint16_t               free_threshold;
    unsigned int           large_buffers_len;
    unsigned int           small_buffers_len;
    unsigned int           large_buffers_size;
    unsigned int           small_buffers_size;
    struct generic_pool_s *shift_buffer_pool;
#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    atomic_size_t in_use;
#endif
    master_pool_t   *large_buffers_mp;
    shift_buffer_t **large_buffers;
    master_pool_t   *small_buffers_mp;
    shift_buffer_t **small_buffers;
    uint8_t          tid;
};

// NOLINTEND
static inline bool isLargeBuffer(buffer_pool_t *pool, shift_buffer_t *buf)
{
    return (bufCap(buf) >= pool->large_buffers_size) ? true : false;
}

static master_pool_item_t *createLargeBufHandle(struct master_pool_s *pool, void *userdata)
{
    (void) pool;
    buffer_pool_t *bpool = userdata;
    return newShiftBuffer(bpool->shift_buffer_pool, bpool->large_buffers_size);
}

static master_pool_item_t *createSmallBufHandle(struct master_pool_s *pool, void *userdata)
{
    (void) pool;
    buffer_pool_t *bpool = userdata;
    return newShiftBuffer(bpool->shift_buffer_pool, bpool->small_buffers_size);
}

static void destroyLargeBufHandle(struct master_pool_s *pool, master_pool_item_t *item, void *userdata)
{
    (void) pool;
    buffer_pool_t *bpool = userdata;
    destroyShiftBuffer(bpool->shift_buffer_pool, item);
}

static void destroySmallBufHandle(struct master_pool_s *pool, master_pool_item_t *item, void *userdata)
{
    (void) pool;
    buffer_pool_t *bpool = userdata;
    destroyShiftBuffer(bpool->shift_buffer_pool, item);
}

static void reChargeLargeBuffers(buffer_pool_t *pool)
{
    const size_t increase = min((pool->cap - pool->large_buffers_len), pool->cap / 2);

    popMasterPoolItems(pool->large_buffers_mp, (void const **) &(pool->large_buffers[pool->large_buffers_len]),
                       increase, pool);

    pool->large_buffers_len += increase;
#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    LOGD("BufferPool: allocated %d new large buffers, %zu are in use", increase, pool->in_use);
#endif
}

static void reChargeSmallBuffers(buffer_pool_t *pool)
{
    const size_t increase = min((pool->cap - pool->small_buffers_len), pool->cap / 2);

    popMasterPoolItems(pool->small_buffers_mp, (void const **) &(pool->small_buffers[pool->small_buffers_len]),
                       increase, pool);

    pool->small_buffers_len += increase;
#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    LOGD("BufferPool: allocated %d new small buffers, %zu are in use", increase, pool->in_use);
#endif
}

static void firstCharge(buffer_pool_t *pool)
{
    reChargeLargeBuffers(pool);
    reChargeSmallBuffers(pool);
}

static void shrinkLargeBuffers(buffer_pool_t *pool)
{
    const size_t decrease = min(pool->large_buffers_len, pool->cap / 2);

    reuseMasterPoolItems(pool->large_buffers_mp, (void **) &(pool->large_buffers[pool->large_buffers_len - decrease]),
                         decrease, pool);

    pool->large_buffers_len -= decrease;

#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    LOGD("BufferPool: freed %d large buffers, %zu are in use", decrease, pool->in_use);
#endif
}

static void shrinkSmallBuffers(buffer_pool_t *pool)
{
    const size_t decrease = min(pool->small_buffers_len, pool->cap / 2);

    reuseMasterPoolItems(pool->small_buffers_mp, (void **) &(pool->small_buffers[pool->small_buffers_len - decrease]),
                         decrease, pool);

    pool->small_buffers_len -= decrease;

#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    LOGD("BufferPool: freed %d small buffers, %zu are in use", decrease, pool->in_use);
#endif
}

shift_buffer_t *popBuffer(buffer_pool_t *pool)
{
#if defined(DEBUG) && defined(BYPASS_BUFFERPOOL)
    return newShiftBuffer(pool->large_buffers_size);
#endif
#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    pool->in_use += 1;
#endif

    if (WW_LIKELY(pool->large_buffers_len > 0))
    {
        --(pool->large_buffers_len);
        return pool->large_buffers[pool->large_buffers_len];
    }
    reChargeLargeBuffers(pool);

    --(pool->large_buffers_len);
    return pool->large_buffers[pool->large_buffers_len];
}

shift_buffer_t *popSmallBuffer(buffer_pool_t *pool)
{
#if defined(DEBUG) && defined(BYPASS_BUFFERPOOL)
    return newShiftBuffer(pool->small_buffer_size);
#endif
#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    pool->in_use += 1;
#endif

    if (WW_LIKELY(pool->small_buffers_len > 0))
    {
        --(pool->small_buffers_len);
        return pool->small_buffers[pool->small_buffers_len];
    }
    reChargeSmallBuffers(pool);

    --(pool->small_buffers_len);
    return pool->small_buffers[pool->small_buffers_len];
}

void reuseBuffer(buffer_pool_t *pool, shift_buffer_t *b)
{
#if defined(DEBUG) && defined(BYPASS_BUFFERPOOL)
    destroyShiftBuffer(b);
    return;
#endif

    if (WW_UNLIKELY(isShallow(b)))
    {
        destroyShiftBuffer(pool->shift_buffer_pool, b);
        return;
    }
#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
    pool->in_use -= 1;
#endif
    if (isLargeBuffer(pool, b))
    {
        if (WW_UNLIKELY(pool->large_buffers_len > pool->free_threshold))
        {
            shrinkLargeBuffers(pool);
        }
        reset(b, pool->large_buffers_size);
        pool->large_buffers[(pool->large_buffers_len)++] = b;
    }
    else
    {
        if (WW_UNLIKELY(pool->small_buffers_len > pool->free_threshold))
        {
            shrinkSmallBuffers(pool);
        }
        reset(b, pool->small_buffers_size);
        pool->small_buffers[(pool->small_buffers_len)++] = b;
    }
}

shift_buffer_t *appendBufferMerge(buffer_pool_t *pool, shift_buffer_t *restrict b1, shift_buffer_t *restrict b2)
{
    unsigned int b1_length = bufLen(b1);
    unsigned int b2_length = bufLen(b2);
    if (b1_length >= b2_length || lCap(b2) < b1_length)
    {
        concatBuffer(b1, b2);
        reuseBuffer(pool, b2);
        return b1;
    }
    shiftl(b2, b1_length);
    memcpy(rawBufMut(b2), rawBuf(b1), b1_length);
    reuseBuffer(pool, b1);
    return b2;
}

static buffer_pool_t *allocBufferPool(struct master_pool_s *mp_large, struct master_pool_s *mp_small,struct generic_pool_s *sb_pool,
                                      unsigned int bufcount, unsigned int large_buffer_size,
                                      unsigned int small_buffer_size)
{
    // stop using pool if you want less, simply uncomment lines in popbuffer and reuseBuffer
    assert(bufcount >= 1);

    // half of the pool is used, other half is free at startup
    bufcount = 2 * bufcount;

    const unsigned long container_len = bufcount * sizeof(shift_buffer_t *);

    buffer_pool_t *ptr_pool = globalMalloc(sizeof(buffer_pool_t));

    *ptr_pool = (buffer_pool_t) {.cap                = bufcount,
                                 .large_buffers_size = large_buffer_size,
                                 .small_buffers_size = small_buffer_size,
                                 .free_threshold     = max(bufcount / 2, (bufcount * 2) / 3),
                                 .shift_buffer_pool              = sb_pool,
#if defined(DEBUG) && defined(BUFFER_POOL_DEBUG)
                                 .in_use = 0,
#endif
                                 .large_buffers_mp = mp_large,
                                 .large_buffers    = globalMalloc(container_len),
                                 .small_buffers_mp = mp_small,
                                 .small_buffers    = globalMalloc(container_len),
                                 };

    installMasterPoolAllocCallbacks(ptr_pool->large_buffers_mp, createLargeBufHandle, destroyLargeBufHandle);
    installMasterPoolAllocCallbacks(ptr_pool->small_buffers_mp, createSmallBufHandle, destroySmallBufHandle);

#ifdef DEBUG
    memset(ptr_pool->large_buffers, 0xFE, container_len);
    memset(ptr_pool->small_buffers, 0xFE, container_len);
#endif

    firstCharge(ptr_pool);
    return ptr_pool;
}

buffer_pool_t *createBufferPool(struct master_pool_s *mp_large, struct master_pool_s *mp_small,
                                struct generic_pool_s *sb_pool)
{
    return allocBufferPool(mp_large, mp_small, sb_pool, BUFFERPOOL_CONTAINER_LEN, BUFFER_SIZE, SMALL_BUFSIZE);
}
