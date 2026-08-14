#include "threadsafe_generic_pool.h"

static threadsafe_generic_pool_t *allocateThreadSafeGenericPool(generic_pool_t *inner_pool)
{
    if (inner_pool == NULL)
    {
        return NULL;
    }

    threadsafe_generic_pool_t *pool = memoryAllocate(sizeof(*pool));
    if (pool == NULL)
    {
        genericpoolDestroy(inner_pool);
        return NULL;
    }

    *pool = (threadsafe_generic_pool_t) {
        .inner_pool = inner_pool,
    };

    if (UNLIKELY(! mutexTryInit(&pool->mutex)))
    {
        genericpoolDestroy(pool->inner_pool);
        memoryFree(pool);
        return NULL;
    }

#if POOL_THREAD_CHECK
    pool->inner_pool->no_thread_check = true;
#endif

    return pool;
}

threadsafe_generic_pool_t *threadsafegenericpoolCreate(master_pool_t *mp, PoolItemCreateHandle create_h,
                                                       PoolItemDestroyHandle destroy_h)
{
    return allocateThreadSafeGenericPool(genericpoolCreate(mp, create_h, destroy_h));
}

threadsafe_generic_pool_t *threadsafegenericpoolCreateWithCapacity(master_pool_t *mp, uint32_t pool_width,
                                                                   PoolItemCreateHandle  create_h,
                                                                   PoolItemDestroyHandle destroy_h)
{
    return allocateThreadSafeGenericPool(genericpoolCreateWithCapacity(mp, pool_width, create_h, destroy_h));
}

threadsafe_generic_pool_t *threadsafegenericpoolCreateWithDefaultAllocator(master_pool_t *mp, uint32_t item_size)
{
    return allocateThreadSafeGenericPool(genericpoolCreateWithDefaultAllocator(mp, item_size));
}

threadsafe_generic_pool_t *threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(master_pool_t *mp,
                                                                                      uint32_t       item_size,
                                                                                      uint32_t       pool_width)
{
    return allocateThreadSafeGenericPool(genericpoolCreateWithDefaultAllocatorAndCapacity(mp, item_size, pool_width));
}

void threadsafegenericpoolDestroy(threadsafe_generic_pool_t *pool)
{
    if (pool == NULL)
    {
        return;
    }

    genericpoolDestroy(pool->inner_pool);
    mutexDestroy(&(pool->mutex));
    memoryFree(pool);
}
