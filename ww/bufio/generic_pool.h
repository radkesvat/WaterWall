#pragma once
#include "wlibc.h"
#include "master_pool.h"

/*
    A growable pool

    preallocates (n) number of buffers at each call to charge(),

    recharing is done autmatically and internally.

    pool width is affected by ww memory profile

    when DEBUG is true, you can:

        define POOL_DEBUG to view debug logs about how many itmes are in use or in pool

        define BYPASS_GENERIC_POOL to bypass the pool for your debug goals or leak finding

*/

// #define POOL_DEBUG
// #define BYPASS_GENERIC_POOL

struct generic_pool_s;
typedef struct generic_pool_s generic_pool_t;

// struct pool_item_s; // void
typedef void pool_item_t;

typedef pool_item_t *(*PoolItemCreateHandle)(struct generic_pool_s *pool);
typedef void (*PoolItemDestroyHandle)(struct generic_pool_s *pool, pool_item_t *item);

#if defined(DEBUG) && defined(POOL_DEBUG)
#define GENERIC_POOL_FIELDS                                                                                            \
    unsigned int          len;                                                                                         \
    unsigned int          cap;                                                                                         \
    unsigned int          free_threshold;                                                                              \
    unsigned int          item_size;                                                                                   \
    atomic_size_t         in_use;                                                                                      \
    PoolItemCreateHandle  create_item_handle;                                                                          \
    PoolItemDestroyHandle destroy_item_handle;                                                                         \
    master_pool_t        *mp;                                                                                          \
    pool_item_t          *available[];
#else

#define GENERIC_POOL_FIELDS                                                                                            \
    unsigned int          len;                                                                                         \
    unsigned int          cap;                                                                                         \
    unsigned int          free_threshold;                                                                              \
    unsigned int          item_size;                                                                                   \
    PoolItemCreateHandle  create_item_handle;                                                                          \
    PoolItemDestroyHandle destroy_item_handle;                                                                         \
    master_pool_t        *mp;                                                                                          \
    pool_item_t          *available[];

#endif

struct generic_pool_s
{
    GENERIC_POOL_FIELDS
};


void poolReCharge(generic_pool_t *pool);
void poolShrink(generic_pool_t *pool);

static inline pool_item_t *popPoolItem(generic_pool_t *pool)
{
#if defined(DEBUG) && defined(BYPASS_GENERIC_POOL)
    return pool->create_item_handle(pool);
#endif

#if defined(DEBUG) && defined(POOL_DEBUG)
    pool->in_use += 1;
#endif

    if (LIKELY(pool->len > 0))
    {
        --(pool->len);
        return pool->available[pool->len];
    }

    poolReCharge(pool);
    --(pool->len);
    return pool->available[pool->len];
}

static inline void reusePoolItem(generic_pool_t *pool, pool_item_t *b)
{
#if defined(DEBUG) && defined(BYPASS_GENERIC_POOL)
    pool->destroy_item_handle(pool, b);
    return;
#endif

#if defined(DEBUG) && defined(POOL_DEBUG)
    pool->in_use -= 1;
#endif
    if (pool->len > pool->free_threshold)
    {
        poolShrink(pool);
    }

    pool->available[(pool->len)++] = b;
}

generic_pool_t *newGenericPool(struct master_pool_s *mp, PoolItemCreateHandle create_h,
                               PoolItemDestroyHandle destroy_h);
generic_pool_t *newGenericPoolWithCap(struct master_pool_s *mp, unsigned int pool_width, PoolItemCreateHandle create_h,
                                      PoolItemDestroyHandle destroy_h);

generic_pool_t *newGenericPoolDefaultAllocator(struct master_pool_s *mp, unsigned int item_size);
generic_pool_t *newGenericPoolDefaultAllocatorWithCap(struct master_pool_s *mp, unsigned int item_size,
                                                      unsigned int pool_width);

#undef BYPASS_GENERIC_POOL
#undef POOL_DEBUG
