#include "buffer_pool.h"
#include "utils/mathutils.h"
#include <assert.h> // for assert
#include <malloc.h>
#include <string.h>
#ifdef DEBUG
#include "loggers/network_logger.h"
#endif

#define LOW_MEMORY  0 // no preallocation (very small)
#define MED1_MEMORY 1 // APPROX 10MB per thread
#define MED2_MEMORY 2 // APPROX 20MB per thread
#define HIG1_MEMORY 3 // APPROX 28MB per thread
#define HIG2_MEMORY 4 // APPROX 36MB per thread

#define MEMORY_PROFILE HIG2_MEMORY // todo (cmake)

#define EVP_READ_BUFSIZE         (1U << 15) // 32K
#define BUFFERPOOL_CONTAINER_LEN ((16 * 4) + ((16 * 16) * MEMORY_PROFILE))
#define BUFFER_SIZE              ((MEMORY_PROFILE < MED2_MEMORY) ? 0 : EVP_READ_BUFSIZE)

static void firstCharge(buffer_pool_t *pool)
{
    for (size_t i = 0; i < BUFFERPOOL_CONTAINER_LEN; i++)
    {
        pool->available[i] = newShiftBuffer(BUFFER_SIZE);
    }
    pool->len = BUFFERPOOL_CONTAINER_LEN;
}

static void reCharge(buffer_pool_t *pool)
{
    const size_t increase = min((2 * BUFFERPOOL_CONTAINER_LEN - pool->len), BUFFERPOOL_CONTAINER_LEN);
    for (size_t i = pool->len; i < (pool->len + increase); i++)
    {
        pool->available[i] = newShiftBuffer(BUFFER_SIZE);
    }
    pool->len += increase;
#ifdef DEBUG
    LOGD("BufferPool: allocated %d new buffers, %zu are in use", increase, pool->in_use);
#endif
}

static void giveMemBackToOs(buffer_pool_t *pool)
{
    const size_t decrease = min(pool->len, BUFFERPOOL_CONTAINER_LEN);

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
    --(pool->len);
    shift_buffer_t *result = pool->available[pool->len];

#ifdef DEBUG
    pool->in_use += 1;
#endif
    return result;
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
    reset(b, BUFFER_SIZE);
    pool->available[pool->len] = b;
    ++(pool->len);
    if (pool->len > (BUFFERPOOL_CONTAINER_LEN + (BUFFERPOOL_CONTAINER_LEN / 2)))
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
        appendBuffer(b1, b2);
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
    const int      container_len = 2 * BUFFERPOOL_CONTAINER_LEN * sizeof(shift_buffer_t *);
    buffer_pool_t *pool          = malloc(sizeof(buffer_pool_t) + container_len);
#ifdef DEBUG
    memset(pool, 0xEE, sizeof(buffer_pool_t) + container_len);
    pool->in_use = 0;
#endif
    memset(pool, 0, sizeof(buffer_pool_t));
    pool->len = 0;
    firstCharge(pool);
    return pool;
}
