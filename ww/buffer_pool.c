#include "buffer_pool.h"
#include "hplatform.h"
#ifdef OS_LINUX
#include <malloc.h>
#endif
#ifdef DEBUG
#include "loggers/network_logger.h"
#endif
#include "shiftbuffer.h"
#include "utils/mathutils.h"
#include "ww.h"
#include <assert.h> // for assert
#include <stdlib.h>
#include <string.h>

// NOLINTBEGIN

#define MEMORY_PROFILE_SMALL    (ram_profile >= kRamProfileM1Memory ? kRamProfileM1Memory : ram_profile)
#define MEMORY_PROFILE_SELECTED ram_profile

#define BASE_READ_BUFSIZE              (1U << 13) // 8k
#define BUFFERPOOL_SMALL_CONTAINER_LEN ((unsigned long) ((MEMORY_PROFILE_SMALL)))
#define BUFFERPOOL_CONTAINER_LEN       ((unsigned long) ((MEMORY_PROFILE_SELECTED)))

#define BUFFER_SIZE_MORE                                                                                               \
    (((int) (MEMORY_PROFILE_SELECTED / 16)) > 1 ? (((int) (MEMORY_PROFILE_SELECTED / 16)) - 1) : (0))


#define BUFFER_SIZE (ram_profile >= kRamProfileS2Memory ? (1U << 15) : (1U << 12))  // 32k (same as nginx file streaming)

// #define BUFFER_SIZE (BASE_READ_BUFSIZE + (BASE_READ_BUFSIZE * BUFFER_SIZE_MORE)) // [8k,32k]

// #define BUFFER_SIZE  (((int) (MEMORY_PROFILE_SELECTED / 16)) >= 1 ? (1U << 15) : (1U << 12) ) //  [4k,32k]

#define BUFFER_SIZE_SMALL (1U << 12) // 4k


// NOLINTEND

static void firstCharge(buffer_pool_t *pool)
{
    for (size_t i = 0; i < (pool->cap / 2); i++)
    {
        pool->available[i] = newShiftBuffer(pool->buffers_size);
    }
    pool->len = pool->cap / 2;
}

static void reCharge(buffer_pool_t *pool)
{
    const size_t increase = min((pool->cap - pool->len), pool->cap / 2);

    for (size_t i = pool->len; i < (pool->len + increase); i++)
    {
        pool->available[i] = newShiftBuffer(pool->buffers_size);
    }
    pool->len += increase;
#if defined(DEBUG) && defined(POOL_DEBUG)
    LOGD("BufferPool: allocated %d new buffers, %zu are in use", increase, pool->in_use);
#endif
}

static void giveMemBackToOs(buffer_pool_t *pool)
{
    const size_t decrease = min(pool->len, pool->cap / 2);

    for (size_t i = pool->len - decrease; i < pool->len; i++)
    {
        destroyShiftBuffer(pool->available[i]);
    }
    pool->len -= decrease;

#if defined(DEBUG) && defined(POOL_DEBUG)
    LOGD("BufferPool: freed %d buffers, %zu are in use", decrease, pool->in_use);
#endif
#ifdef OS_LINUX
    malloc_trim(0);
#endif
}

shift_buffer_t *popBuffer(buffer_pool_t *pool)
{
#if defined(DEBUG) && defined(BYPASS_POOL)
    return newShiftBuffer(pool->buffers_size);
#endif

    if (pool->len <= 0)
    {
        reCharge(pool);
    }

#if defined(DEBUG) && defined(BYPASS_POOL)
    pool->in_use += 1;
#endif
    --(pool->len);
    return pool->available[pool->len];
}

void reuseBuffer(buffer_pool_t *pool, shift_buffer_t *b)
{
#if defined(DEBUG) && defined(BYPASS_POOL)
    destroyShiftBuffer(b);
    return;
#endif

    if (isShallow(b))
    {
        destroyShiftBuffer(b);
        return;
    }
#if defined(DEBUG) && defined(BYPASS_POOL)
    pool->in_use -= 1;
#endif
    if (pool->len > pool->free_threshould)
    {
        giveMemBackToOs(pool);
    }
    reset(b, pool->buffers_size);
    pool->available[(pool->len)++] = b;
}

shift_buffer_t *appendBufferMerge(buffer_pool_t *pool, shift_buffer_t *restrict b1, shift_buffer_t *restrict b2)
{
    unsigned int b1_length = bufLen(b1);
    unsigned int b2_length = bufLen(b2);
    if (b1_length >= b2_length)
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

static buffer_pool_t *allocBufferPool(unsigned long bufcount,unsigned int buffer_size) // NOLINT
{
    // stop using pool if you want less, simply uncomment lines in popbuffer and reuseBuffer
    assert(bufcount >= 1);

    // half of the pool is used, other half is free at startup
    bufcount = 2 * bufcount;

    const unsigned long container_len = bufcount * sizeof(shift_buffer_t *);
    buffer_pool_t      *pool          = malloc(sizeof(buffer_pool_t) + container_len);
#ifdef DEBUG
    memset(pool, 0xEE, sizeof(buffer_pool_t) + container_len);
#endif
    memset(pool, 0, sizeof(buffer_pool_t));
    pool->cap             = bufcount;
    pool->buffers_size    = buffer_size;
    pool->free_threshould = (pool->cap * 2) / 3;
    firstCharge(pool);
    return pool;
}

buffer_pool_t *createBufferPool(void)
{
    return allocBufferPool(BUFFERPOOL_CONTAINER_LEN,BUFFER_SIZE);
}

buffer_pool_t *createSmallBufferPool(void)
{
    return allocBufferPool(BUFFERPOOL_SMALL_CONTAINER_LEN,BUFFER_SIZE_SMALL);
}
