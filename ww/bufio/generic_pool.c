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

    masterpoolGetItems(pool->mp, &(pool->available[pool->len]), increase, pool);

    pool->len += increase;
#if POOL_DEBUG == 1
    wlogd("BufferPool: allocated %d new buffers, %zu are in use", increase, genericpoolGetInUse(pool));
#endif
}

void genericpoolShrink(generic_pool_t *pool)
{
    const uint32_t decrease = (pool->len < (pool->cap / 2) ? pool->len : (pool->cap / 2));

    masterpoolReuseItems(pool->mp, &(pool->available[pool->len - decrease]), decrease);

    pool->len -= decrease;

#if POOL_DEBUG == 1
    wlogd("BufferPool: freed %d buffers, %zu are in use", decrease, genericpoolGetInUse(pool));
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

static bool genericpoolTryComputeGeometry(uint32_t pool_width, uint32_t *capacity_out, uint32_t *free_threshold_out,
                                          size_t *allocation_size_out)
{
    if (capacity_out == NULL || free_threshold_out == NULL || allocation_size_out == NULL)
    {
        return false;
    }

    pool_width = max((uint32_t) 1, pool_width);
    if (pool_width > UINT32_MAX / 2U)
    {
        return false;
    }
    const uint32_t capacity = pool_width * 2U;

    size_t container_len;
    if (! memoryTryComputeArraySize(capacity, sizeof(pool_item_t *), &container_len) ||
        container_len > SIZE_MAX - sizeof(generic_pool_t))
    {
        return false;
    }
    const size_t required_size = sizeof(generic_pool_t) + container_len;

    *capacity_out        = capacity;
    *free_threshold_out  = (uint32_t) (((uint64_t) capacity * 2U) / 3U);
    *allocation_size_out = required_size;
    return true;
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
    uint32_t capacity;
    uint32_t free_threshold;
    size_t   required_size;
    if (mp == NULL || create_h == NULL || destroy_h == NULL ||
        ! genericpoolTryComputeGeometry(pool_width, &capacity, &free_threshold, &required_size))
    {
        return NULL;
    }
    generic_pool_t *pool_ptr = memoryAllocate(required_size);
    if (pool_ptr == NULL)
    {
        return NULL;
    }
#ifdef DEBUG
    memorySet(pool_ptr, 0xEB, required_size);
#endif
    *pool_ptr = (generic_pool_t) {
        .cap                 = capacity,
        .free_threshold      = free_threshold,
        .item_size           = item_size,
        .mp                  = mp,
        .create_item_handle  = create_h,
        .destroy_item_handle = destroy_h,

#if POOL_THREAD_CHECK
        .tid             = 0,
        .no_thread_check = false,
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
    if (pool == NULL)
    {
        return;
    }

    for (uint32_t i = 0; i < pool->len; ++i)
    {
        pool->destroy_item_handle(pool->available[i]);
    }
    memoryFree(pool);
}

void genericpoolReuseItemShared(generic_pool_t *pool, pool_item_t *item)
{
    assert(pool != NULL);
    assert(item != NULL);

#if BYPASS_GENERIC_POOL == 1
    pool->destroy_item_handle(item);
    masterpoolRecordReturn(pool->mp);
    return;
#endif

    assert(genericpoolGetInUse(pool) > 0);

    /* Keep the family-wide checked-out count non-zero until the shared return
     * is complete. A concurrent owner teardown therefore cannot release either
     * this metadata or its master pool while they are still in use. */
    masterpoolReuseItems(pool->mp, &item, 1);
    masterpoolRecordReturn(pool->mp);
}
