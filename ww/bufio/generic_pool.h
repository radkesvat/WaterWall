#pragma once
#include "master_pool.h"
#include "wlibc.h"
#include "wthread.h"

/*
    A growable pool

    preallocates (n) number of buffers at each call to charge(),

    recharing is done autmatically and internally.

    pool width is affected by ww memory profile

    when DEBUG is true, you can:


*/

typedef struct generic_pool_s generic_pool_t;

// struct pool_item_s; // void
typedef void pool_item_t;

typedef pool_item_t *(*PoolItemCreateHandle)(generic_pool_t *pool);
typedef void (*PoolItemDestroyHandle)(generic_pool_t *pool, pool_item_t *item);

#if POOL_DEBUG == 1
#define GENERIC_POOL_FIELDS                                                                                            \
    uint32_t              len;                                                                                         \
    uint32_t              cap;                                                                                         \
    uint32_t              free_threshold;                                                                              \
    uint32_t              item_size;                                                                                   \
    atomic_size_t         in_use;                                                                                      \
    PoolItemCreateHandle  create_item_handle;                                                                          \
    PoolItemDestroyHandle destroy_item_handle;                                                                         \
    master_pool_t        *mp;                                                                                          \
    pool_item_t          *available[];
#else

#define GENERIC_POOL_FIELDS                                                                                            \
    uint32_t              len;                                                                                         \
    uint32_t              cap;                                                                                         \
    uint32_t              free_threshold;                                                                              \
    uint32_t              item_size;                                                                                   \
    PoolItemCreateHandle  create_item_handle;                                                                          \
    PoolItemDestroyHandle destroy_item_handle;                                                                         \
    master_pool_t        *mp;                                                                                          \
    pool_item_t          *available[];

#endif

struct generic_pool_s
{

#if POOL_THREAD_CHECK
    tid_t tid;
    bool  no_thread_check; // if true, we don't check the thread ID

#endif

    GENERIC_POOL_FIELDS
};

/**
 * Checks if the current thread has access to the pool.
 * This has no effect on non-debug builds.
 * @param pool The generic pool to check access for.
 */
#if POOL_THREAD_CHECK
static inline void genericpoolDebugCheckThreadAccess(generic_pool_t *pool)
{
    if (pool->no_thread_check)
    {
        // If no thread check is enabled, skip the thread ID check
        return;
    }

    if (UNLIKELY(pool->tid == 0))
    {
        // This is the first access, set the thread ID
        pool->tid = getTID();
    }
    if (UNLIKELY(pool->tid != getTID()))
    {
        printError("GenericPool: Access from wrong thread %d, expected %d", getTID(), pool->tid);
        terminateProgram(1);
    }
}
#else
#define genericpoolDebugCheckThreadAccess(pool) ((void) 0)
#endif

/**
 * Recharges the pool by preallocating a number of buffers.
 * @param pool The generic pool to recharge.
 */
void genericpoolReCharge(generic_pool_t *pool);

/**
 * Shrinks the pool by releasing a number of buffers.
 * @param pool The generic pool to shrink.
 */
void genericpoolShrink(generic_pool_t *pool);

/**
 * Retrieves an item from the pool.
 * @param pool The generic pool to retrieve an item from.
 * @return A pointer to the retrieved item.
 */
static inline pool_item_t *genericpoolGetItem(generic_pool_t *pool)
{
#if BYPASS_GENERIC_POOL == 1
    return pool->create_item_handle(pool);
#endif

#if POOL_DEBUG == 1
    pool->in_use += 1;
#endif
    genericpoolDebugCheckThreadAccess(pool);

    if (LIKELY(pool->len > 0))
    {
        --(pool->len);
        return pool->available[pool->len];
    }

    genericpoolReCharge(pool);
    --(pool->len);
    return pool->available[pool->len];
}

/**
 * Reuses an item by returning it to the pool.
 * @param pool The generic pool to return the item to.
 * @param b The item to be reused.
 */
static inline void genericpoolReuseItem(generic_pool_t *pool, pool_item_t *b)
{
#if BYPASS_GENERIC_POOL == 1
    pool->destroy_item_handle(pool, b);
    return;
#endif

#if POOL_DEBUG == 1
    pool->in_use -= 1;
#endif
    genericpoolDebugCheckThreadAccess(pool);

    if (pool->len > pool->free_threshold)
    {
        genericpoolShrink(pool);
    }

    pool->available[(pool->len)++] = b;
}

/**
 * Gets the item size of the pool.
 * @param pool The generic pool to get the item size from.
 * @return The item size of the pool.
 */
static inline uint32_t genericpoolGetItemSize(generic_pool_t *pool)
{
    return pool->item_size;
}

/**
 * Sets the item size of the pool.
 * @param pool The generic pool to set the item size for.
 * @param item_size The item size to set.
 */
static inline void genericpoolSetItemSize(generic_pool_t *pool, uint32_t item_size)
{
    pool->item_size = item_size;
}

/**
 * Creates a generic pool with custom create and destroy handlers.
 * @param mp The master pool.
 * @param create_h The handler to create pool items.
 * @param destroy_h The handler to destroy pool items.
 * @return A pointer to the created generic pool.
 */
generic_pool_t *genericpoolCreate(master_pool_t *mp, PoolItemCreateHandle create_h, PoolItemDestroyHandle destroy_h);

/**
 * Creates a generic pool with custom create and destroy handlers and a specified capacity.
 * @param mp The master pool.
 * @param pool_width The width of the pool.
 * @param create_h The handler to create pool items.
 * @param destroy_h The handler to destroy pool items.
 * @return A pointer to the created generic pool.
 */
generic_pool_t *genericpoolCreateWithCapacity(master_pool_t *mp, uint32_t pool_width, PoolItemCreateHandle create_h,
                                              PoolItemDestroyHandle destroy_h);

/**
 * Creates a generic pool with a default allocator.
 * @param mp The master pool.
 * @param item_size The size of each item in the pool.
 * @return A pointer to the created generic pool.
 */
generic_pool_t *genericpoolCreateWithDefaultAllocator(master_pool_t *mp, uint32_t item_size);

/**
 * Creates a generic pool with a default allocator and a specified capacity.
 * @param mp The master pool.
 * @param item_size The size of each item in the pool.
 * @param pool_width The width of the pool.
 * @return A pointer to the created generic pool.
 */
generic_pool_t *genericpoolCreateWithDefaultAllocatorAndCapacity(master_pool_t *mp, uint32_t item_size,
                                                                 uint32_t pool_width);

/**
 * Destroys the generic pool and frees its resources.
 * @param pool The generic pool to destroy.
 */
void genericpoolDestroy(generic_pool_t *pool);
