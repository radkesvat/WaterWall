#include "buffer_pool.h"
#include "hlog.h"
#include "shiftbuffer.h"
#include "utils/mathutils.h"
#include <assert.h> // for assert
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#ifdef DEBUG
#endif

enum
{
    kLowMemory  = 0, // no preallocation (very small)
    kMeD1Memory = 1, // APPROX 20MB per thread
    kMeD2Memory = 2, // APPROX 40MB per thread
    kHiG1Memory = 3, // APPROX 56MB per thread
    kHiG2Memory = 4  // APPROX 72MB per thread
};

#define MEMORY_PROFILE kHiG2Memory // todo (cmake)

enum
{
    BASE_READ_BUFSIZE = (1U << 13) // 8K
};

#define BUFFERPOOL_SMALL_CONTAINER_LEN ((unsigned long) ((16 * (16 * kMeD1Memory))))
#define BUFFERPOOL_CONTAINER_LEN       ((unsigned long) ((16 * (16 * (MEMORY_PROFILE > 0 ? MEMORY_PROFILE : 1)))))

#define BUFFER_SIZE (BASE_READ_BUFSIZE * (MEMORY_PROFILE > 0 ? MEMORY_PROFILE : 1))

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
    const size_t increase = min((pool->cap - pool->len) - 1, pool->cap / 2);

    for (size_t i = pool->len; i < (pool->len + increase); i++)
    {
        pool->available[i] = newShiftBuffer(pool->buffers_size);
    }
    pool->len += increase;
#ifdef DEBUG
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

#ifdef DEBUG
    LOGD("BufferPool: freed %d buffers, %zu are in use", decrease, pool->in_use);
#endif

    malloc_trim(0); // y tho?
}

shift_buffer_t *popBuffer(buffer_pool_t *pool)
{
    // return newShiftBuffer(BUFFER_SIZE);
    if (pool->len <= 0)
    {
        reCharge(pool);
    }

#ifdef DEBUG
    pool->in_use += 1;
#endif
    --(pool->len);
    return pool->available[pool->len];
}

void reuseBuffer(buffer_pool_t *pool, shift_buffer_t *b)
{
    // destroyShiftBuffer(b);
    // return;
    if (*(b->refc) > 1)
    {
        destroyShiftBuffer(b);
        return;
    }
#ifdef DEBUG
    pool->in_use -= 1;
#endif
    reset(b, pool->buffers_size);
    pool->available[(pool->len)++] = b;
    if (pool->len > pool->free_threshould)
    {
        giveMemBackToOs(pool);
    }
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

buffer_pool_t *createBufferPool()
{
    const unsigned long count_max     = 2 * BUFFERPOOL_CONTAINER_LEN;
    const unsigned long container_len = count_max * sizeof(shift_buffer_t *);
    buffer_pool_t      *pool          = malloc(sizeof(buffer_pool_t) + container_len);
#ifdef DEBUG
    memset(pool, 0xEE, sizeof(buffer_pool_t) + container_len);
#endif
    memset(pool, 0, sizeof(buffer_pool_t));
    pool->cap             = count_max;
    pool->buffers_size    = BUFFER_SIZE;
    pool->free_threshould = (pool->cap * 2) / 3;
    firstCharge(pool);
    return pool;
}

buffer_pool_t *createSmallBufferPool()
{
    const unsigned long count_max     = 2 * BUFFERPOOL_SMALL_CONTAINER_LEN;
    const unsigned long container_len = count_max * sizeof(shift_buffer_t *);
    buffer_pool_t      *pool          = malloc(sizeof(buffer_pool_t) + container_len);
#ifdef DEBUG
    memset(pool, 0xEE, sizeof(buffer_pool_t) + container_len);
#endif
    memset(pool, 0, sizeof(buffer_pool_t));
    pool->cap             = count_max;
    pool->buffers_size    = BUFFER_SIZE;
    pool->free_threshould = (pool->cap * 2) / 3;
    firstCharge(pool);
    return pool;
}
