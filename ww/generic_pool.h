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

// #define POOL_DEBUG
// #define BYPASS_POOL

struct generic_pool_s;
// struct pool_item_s; // void
typedef void pool_item_t;

typedef pool_item_t *(*PoolItemCreateHandle)(struct generic_pool_s *pool);
typedef void (*PoolItemDestroyHandle)(struct generic_pool_s *pool, pool_item_t *item);

#if defined(DEBUG) && defined(POOL_DEBUG)
#define GENERIC_POOL_FIELDS                                                                                            \
    unsigned int          len;                                                                                         \
    unsigned int          cap;                                                                                         \
    unsigned int          free_threshould;                                                                             \
    const unsigned int    item_size;                                                                                   \
    atomic_size_t         in_use;                                                                                      \
    PoolItemCreateHandle  create_item_handle;                                                                          \
    PoolItemDestroyHandle destroy_item_handle;                                                                         \
    pool_item_t          *available[];
#else

#define GENERIC_POOL_FIELDS                                                                                            \
    unsigned int          len;                                                                                         \
    unsigned int          cap;                                                                                         \
    unsigned int          free_threshould;                                                                             \
    const unsigned int    item_size;                                                                                   \
    PoolItemCreateHandle  create_item_handle;                                                                          \
    PoolItemDestroyHandle destroy_item_handle;                                                                         \
    pool_item_t          *available[];

#endif

struct generic_pool_s
{
    GENERIC_POOL_FIELDS
};

typedef struct generic_pool_s generic_pool_t;

void poolReCharge(generic_pool_t *pool);
void poolShrink(generic_pool_t *pool);

static inline pool_item_t *popPoolItem(generic_pool_t *pool)
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

static inline void reusePoolItem(generic_pool_t *pool, pool_item_t *b)
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
generic_pool_t *newGenericPoolWithCap(unsigned int pool_width, PoolItemCreateHandle create_h,
                                      PoolItemDestroyHandle destroy_h);

generic_pool_t *newGenericPoolDefaultAllocator(unsigned int item_size);
generic_pool_t *newGenericPoolDefaultAllocatorWithCap(unsigned int item_size, unsigned int pool_width);

#undef BYPASS_POOL
#undef POOL_DEBUG
