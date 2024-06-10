#pragma once
#include <stdatomic.h>
#include <stddef.h>
#ifdef OS_LINUX
#include <malloc.h>
#endif

/*
    A growable pool, very simple.

    preallocates (n) number of buffers at each call to charge(),

    recharing is done autmatically and internally.

    pool width is affected by ww memory profile

    when DEBUG is true, you can:

        define POOL_DEBUG to view debug logs about how many itmes are in use or in pool

        define BYPASS_POOL to bypass the pool for your debug goals or leak finding

*/

struct generic_pool_s;

typedef void pool_item_t;
typedef pool_item_t *(*PoolItemCreateHandle)(struct generic_pool_s *pool);
typedef void (*PoolItemDestroyHandle)(struct generic_pool_s *pool, pool_item_t *item);

#if defined(DEBUG) && defined(POOL_DEBUG)
#define GENERIC_POOL_FIELDS                                                                                            \
    unsigned int          len;                                                                                         \
    unsigned int          cap;                                                                                         \
    unsigned int          free_threshould;                                                                             \
    atomic_size_t         in_use;                                                                                      \
    PoolItemCreateHandle  create_item_handle;                                                                          \
    PoolItemDestroyHandle destroy_item_handle;                                                                         \
    pool_item_t          *available[];
#else

#define GENERIC_POOL_FIELDS                                                                                            \
    unsigned int          len;                                                                                         \
    unsigned int          cap;                                                                                         \
    unsigned int          free_threshould;                                                                             \
    PoolItemCreateHandle  create_item_handle;                                                                          \
    PoolItemDestroyHandle destroy_item_handle;                                                                         \
    pool_item_t          *available[];

#endif

struct generic_pool_s
{
    GENERIC_POOL_FIELDS
};

typedef struct generic_pool_s generic_pool_t;

inline void poolReCharge(generic_pool_t *pool)
{
    const size_t increase = ((pool->cap - pool->len) < (pool->cap) / 2 ? (pool->cap - pool->len) : (pool->cap / 2));

    for (size_t i = pool->len; i < (pool->len + increase); i++)
    {
        pool->available[i] = pool->create_item_handle(pool);
    }
    pool->len += increase;
#if defined(DEBUG) && defined(POOL_DEBUG)
    LOGD("BufferPool: allocated %d new buffers, %zu are in use", increase, pool->in_use);
#endif
}

inline void poolShrink(generic_pool_t *pool)
{
    const size_t decrease = (pool->len < (pool->cap / 2) ? pool->len : (pool->cap / 2));

    for (size_t i = pool->len - decrease; i < pool->len; i++)
    {
        pool->destroy_item_handle(pool, pool->available[i]);
    }
    pool->len -= decrease;

#if defined(DEBUG) && defined(POOL_DEBUG)
    LOGD("BufferPool: freed %d buffers, %zu are in use", decrease, pool->in_use);
#endif
#ifdef OS_LINUX
    malloc_trim(0);
#endif
}

inline pool_item_t *popPoolItem(generic_pool_t *pool)
{
#if defined(DEBUG) && defined(BYPASS_POOL)
    return pool->create_item_handle(pool);
#endif

    if (pool->len <= 0)
    {
        poolReCharge(pool);
    }

#if defined(DEBUG) && defined(POOL_DEBUG)
    pool->in_use += 1;
#endif
    --(pool->len);
    return pool->available[pool->len];
}

inline void reusePoolItem(generic_pool_t *pool, pool_item_t *b)
{
#if defined(DEBUG) && defined(BYPASS_POOL)
    pool->destroy_item_handle(pool, b);
    return;
#endif

#if defined(DEBUG) && defined(POOL_DEBUG)
    pool->in_use -= 1;
#endif
    if (pool->len > pool->free_threshould)
    {
        poolShrink(pool);
    }

    pool->available[(pool->len)++] = b;
}

generic_pool_t *newGenericPool(PoolItemCreateHandle create_h, PoolItemDestroyHandle destroy_h);
generic_pool_t *newGenericPoolWithSize(unsigned long pool_width, PoolItemCreateHandle create_h,
                                       PoolItemDestroyHandle destroy_h);

#undef BYPASS_POOL
#undef POOL_DEBUG
