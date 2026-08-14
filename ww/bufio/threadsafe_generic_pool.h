#pragma once

/*
 * Mutex-protected wrapper around generic_pool_t for cross-thread access.
 */

#include "generic_pool.h"
#include "wmutex.h"

typedef struct threadsafe_generic_pool_s
{
    wmutex_t        mutex;
    generic_pool_t *inner_pool;
} threadsafe_generic_pool_t;

static inline pool_item_t *threadsafegenericpoolGetItem(threadsafe_generic_pool_t *pool)
{
    pool_item_t *item;

    mutexLock(&(pool->mutex));
    item = genericpoolGetItem(pool->inner_pool);
    mutexUnlock(&(pool->mutex));

    return item;
}

static inline void threadsafegenericpoolReuseItem(threadsafe_generic_pool_t *pool, pool_item_t *item)
{
    mutexLock(&(pool->mutex));
    genericpoolReuseItem(pool->inner_pool, item);
    mutexUnlock(&(pool->mutex));
}

static inline uint32_t threadsafegenericpoolGetItemSize(threadsafe_generic_pool_t *pool)
{
    uint32_t item_size;

    mutexLock(&(pool->mutex));
    item_size = genericpoolGetItemSize(pool->inner_pool);
    mutexUnlock(&(pool->mutex));

    return item_size;
}

static inline void threadsafegenericpoolSetItemSize(threadsafe_generic_pool_t *pool, uint32_t item_size)
{
    mutexLock(&(pool->mutex));
    genericpoolSetItemSize(pool->inner_pool, item_size);
    mutexUnlock(&(pool->mutex));
}

/* All wrapper constructors return NULL when either inner-pool metadata or the
 * mutex wrapper allocation fails. Callers must check before publication. */
threadsafe_generic_pool_t *threadsafegenericpoolCreate(master_pool_t *mp, PoolItemCreateHandle create_h,
                                                       PoolItemDestroyHandle destroy_h);

threadsafe_generic_pool_t *threadsafegenericpoolCreateWithCapacity(master_pool_t *mp, uint32_t pool_width,
                                                                   PoolItemCreateHandle  create_h,
                                                                   PoolItemDestroyHandle destroy_h);

threadsafe_generic_pool_t *threadsafegenericpoolCreateWithDefaultAllocator(master_pool_t *mp, uint32_t item_size);

threadsafe_generic_pool_t *threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(master_pool_t *mp,
                                                                                      uint32_t       item_size,
                                                                                      uint32_t       pool_width);

void threadsafegenericpoolDestroy(threadsafe_generic_pool_t *pool);
