/*
 * Implements generic pooled allocation with master-pool fallback.
 */

#include "generic_pool.h"
#include "global_state.h"

#if POOL_DEBUG == 1
#include "loggers/internal_logger.h"
#endif
#define GENERIC_POOL_DEFAULT_WIDTH ((uint32_t) ((RAM_PROFILE)))

/**
 * Creates a pool item using the provided create handler.
 * @param pool The master pool.
 * @param userdata User data passed to the create handler.
 * @return A pointer to the created pool item.
 */
static master_pool_item_t *poolCreateItemHandle(void *userdata)
{
    generic_pool_t *gpool = userdata;

    return gpool->create_item_handle(gpool);
}

void genericpoolReCharge(generic_pool_t *pool)
{
    const uint32_t increase = min((pool->cap - pool->len), (pool->cap) / 2);

    masterpoolGetItems(pool->mp, (void const **) &(pool->available[pool->len]), increase, pool);

    pool->len += increase;
#if POOL_DEBUG == 1
    wlogd("BufferPool: allocated %d new buffers, %zu are in use", increase, pool->in_use);
#endif
}

void genericpoolShrink(generic_pool_t *pool)
{
    const uint32_t decrease = (pool->len < (pool->cap / 2) ? pool->len : (pool->cap / 2));

    masterpoolReuseItems(pool->mp, &(pool->available[pool->len - decrease]), decrease);

    pool->len -= decrease;

#if POOL_DEBUG == 1
    wlogd("BufferPool: freed %d buffers, %zu are in use", decrease, pool->in_use);
#endif
}

/**
 * Performs the initial charge of the pool.
 * @param pool The generic pool to charge.
 */
static void poolFirstCharge(generic_pool_t *pool)
{
    genericpoolReCharge(pool);
}

/**
 * @brief Allocate and initialize a generic pool instance.
 *
 * @param mp Backing master pool.
 * @param item_size Item size for default allocator mode.
 * @param pool_width Requested pool width before internal scaling.
 * @param create_h Item creation callback.
 * @param destroy_h Item destruction callback.
 * @return generic_pool_t* Initialized pool object.
 */
static generic_pool_t *allocateGenericPool(master_pool_t *mp, uint32_t item_size, uint32_t pool_width,
                                           PoolItemCreateHandle create_h, PoolItemDestroyHandle destroy_h)
{

    pool_width = max((uint32_t) 1, pool_width);

    // half of the pool is used, other half is free at startup
    pool_width = 2 * pool_width;

    const unsigned long container_len = pool_width * sizeof(pool_item_t *);
    generic_pool_t     *pool_ptr      = memoryAllocate(sizeof(generic_pool_t) + container_len);
#ifdef DEBUG
    memorySet(pool_ptr, 0xEB, sizeof(generic_pool_t) + container_len);
#endif
    *pool_ptr = (generic_pool_t) {
        .cap                 = pool_width,
        .free_threshold      = max(pool_width / 2, (pool_width * 2) / 3),
        .item_size           = item_size,
        .mp                  = mp,
        .create_item_handle  = create_h,
        .destroy_item_handle = destroy_h,

#if POOL_THREAD_CHECK
        .tid             = 0,
        .no_thread_check = false,
#endif

#if POOL_DEBUG == 1
        .in_use = 0,
#endif

    };
    masterpoolInstallCallBacks(pool_ptr->mp, poolCreateItemHandle, destroy_h);
    // poolFirstCharge(pool_ptr);
    return pool_ptr;
}

/**
 * Default allocator for pool items.
 * @param pool The generic pool.
 * @return A pointer to the allocated pool item.
 */
static pool_item_t *poolDefaultAllocator(generic_pool_t *pool)
{
    return memoryAllocate(pool->item_size);
}

/**
 * Default deallocator for pool items.
 * @param item The pool item to deallocate.
 */
static void poolDefaultDeallocator(pool_item_t *item)
{
    memoryFree(item);
}

/**
 * Default cache-line aligned allocator for pool items.
 * @param pool The generic pool.
 * @return A pointer to the allocated pool item.
 */
static pool_item_t *poolDefaultCacheAlignedAllocator(generic_pool_t *pool)
{
    return memoryAllocateCacheAligned(pool->item_size);
}

/**
 * Default cache-line aligned deallocator for pool items.
 * @param item The pool item to deallocate.
 */
static void poolDefaultCacheAlignedDeallocator(pool_item_t *item)
{
    memoryFreeAligned(item);
}

generic_pool_t *genericpoolCreate(master_pool_t *mp, PoolItemCreateHandle create_h, PoolItemDestroyHandle destroy_h)
{
    return allocateGenericPool(mp, 0, GENERIC_POOL_DEFAULT_WIDTH, create_h, destroy_h);
}

generic_pool_t *genericpoolCreateWithCapacity(master_pool_t *mp, uint32_t pool_width, PoolItemCreateHandle create_h,
                                              PoolItemDestroyHandle destroy_h)
{
    return allocateGenericPool(mp, 0, pool_width, create_h, destroy_h);
}

generic_pool_t *genericpoolCreateWithDefaultAllocator(master_pool_t *mp, uint32_t item_size)
{
    return allocateGenericPool(mp, item_size, GENERIC_POOL_DEFAULT_WIDTH, poolDefaultAllocator, poolDefaultDeallocator);
}

generic_pool_t *genericpoolCreateWithDefaultAllocatorAndCapacity(master_pool_t *mp, uint32_t item_size,
                                                                 uint32_t pool_width)
{
    return allocateGenericPool(mp, item_size, pool_width, poolDefaultAllocator, poolDefaultDeallocator);
}

generic_pool_t *genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(master_pool_t *mp, uint32_t item_size,
                                                                             uint32_t pool_width)
{
    return allocateGenericPool(
        mp, item_size, pool_width, poolDefaultCacheAlignedAllocator, poolDefaultCacheAlignedDeallocator);
}

void genericpoolDestroy(generic_pool_t *pool)
{
    for (uint32_t i = 0; i < pool->len; ++i)
    {
        pool->destroy_item_handle(pool->available[i]);
    }
    memoryFree(pool);
}
