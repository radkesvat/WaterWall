#include "generic_pool.h"
#include "global_state.h"

#ifdef POOL_DEBUG
#include "loggers/internal_logger.h"
#endif
#define GENERIC_POOL_DEFAULT_WIDTH ((uint32_t) ((RAM_PROFILE)))

/**
 * Creates a pool item using the provided create handler.
 * @param pool The master pool.
 * @param userdata User data passed to the create handler.
 * @return A pointer to the created pool item.
 */
static master_pool_item_t *poolCreateItemHandle(master_pool_t *pool, void *userdata)
{
    discard pool;
    generic_pool_t *gpool = userdata;

    return gpool->create_item_handle(gpool);
}

/**
 * Destroys a pool item using the provided destroy handler.
 * @param pool The master pool.
 * @param item The pool item to destroy.
 * @param userdata User data passed to the destroy handler.
 */
static void poolDestroyItemHandle(master_pool_t *pool, master_pool_item_t *item, void *userdata)
{
    discard pool;
    generic_pool_t *gpool = userdata;

    gpool->destroy_item_handle(gpool, item);
}

/**
 * Recharges the pool by preallocating a number of buffers.
 * @param pool The generic pool to recharge.
 */
void genericpoolReCharge(generic_pool_t *pool)
{
    const uint32_t increase = min((pool->cap - pool->len), (pool->cap) / 2);

    masterpoolGetItems(pool->mp, (void const **) &(pool->available[pool->len]), increase, pool);

    pool->len += increase;
#if defined(POOL_DEBUG)
    wlogd("BufferPool: allocated %d new buffers, %zu are in use", increase, pool->in_use);
#endif
}

/**
 * Shrinks the pool by releasing a number of buffers.
 * @param pool The generic pool to shrink.
 */
void genericpoolShrink(generic_pool_t *pool)
{
    const uint32_t decrease = (pool->len < (pool->cap / 2) ? pool->len : (pool->cap / 2));

    masterpoolReuseItems(pool->mp, &(pool->available[pool->len - decrease]), decrease, pool);

    pool->len -= decrease;

#if defined(POOL_DEBUG)
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
 * Allocates and initializes a generic pool.
 * @param mp The master pool.
 * @param item_size The size of each item in the pool.
 * @param pool_width The width of the pool.
 * @param create_h The handler to create pool items.
 * @param destroy_h The handler to destroy pool items.
 * @return A pointer to the allocated generic pool.
 */
static generic_pool_t *allocateGenericPool(master_pool_t *mp, uint32_t item_size, uint32_t pool_width,
                                           PoolItemCreateHandle create_h, PoolItemDestroyHandle destroy_h)
{

    pool_width = max((uint32_t)1, pool_width);

    // half of the pool is used, other half is free at startup
    pool_width = 2 * pool_width;

    const unsigned long container_len = pool_width * sizeof(pool_item_t *);
    generic_pool_t     *pool_ptr      = memoryAllocate(sizeof(generic_pool_t) + container_len);
#ifdef DEBUG
    memorySet(pool_ptr, 0xEB, sizeof(generic_pool_t) + container_len);
#endif
    *pool_ptr = (generic_pool_t){.cap                 = pool_width,
                                 .free_threshold      = max(pool_width / 2, (pool_width * 2) / 3),
                                 .item_size           = item_size,
                                 .mp                  = mp,
                                 .create_item_handle  = create_h,
                                 .destroy_item_handle = destroy_h};
    masterpoolInstallCallBacks(pool_ptr->mp, poolCreateItemHandle, poolDestroyItemHandle);
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
 * @param pool The generic pool.
 * @param item The pool item to deallocate.
 */
static void poolDefaultDeallocator(generic_pool_t *pool, pool_item_t *item)
{
    discard pool;
    memoryFree(item);
}

/**
 * Creates a generic pool with custom create and destroy handlers.
 * @param mp The master pool.
 * @param create_h The handler to create pool items.
 * @param destroy_h The handler to destroy pool items.
 * @return A pointer to the created generic pool.
 */
generic_pool_t *genericpoolCreate(master_pool_t *mp, PoolItemCreateHandle create_h, PoolItemDestroyHandle destroy_h)
{
    return allocateGenericPool(mp, 0, GENERIC_POOL_DEFAULT_WIDTH, create_h, destroy_h);
}

/**
 * Creates a generic pool with custom create and destroy handlers and a specified capacity.
 * @param mp The master pool.
 * @param pool_width The width of the pool.
 * @param create_h The handler to create pool items.
 * @param destroy_h The handler to destroy pool items.
 * @return A pointer to the created generic pool.
 */
generic_pool_t *genericpoolCreateWithCapacity(master_pool_t *mp, uint32_t pool_width, PoolItemCreateHandle create_h,
                                              PoolItemDestroyHandle destroy_h)
{
    return allocateGenericPool(mp, 0, pool_width, create_h, destroy_h);
}

/**
 * Creates a generic pool with a default allocator.
 * @param mp The master pool.
 * @param item_size The size of each item in the pool.
 * @return A pointer to the created generic pool.
 */
generic_pool_t *genericpoolCreateWithDefaultAllocator(master_pool_t *mp, uint32_t item_size)
{
    return allocateGenericPool(mp, item_size, GENERIC_POOL_DEFAULT_WIDTH, poolDefaultAllocator, poolDefaultDeallocator);
}

/**
 * Creates a generic pool with a default allocator and a specified capacity.
 * @param mp The master pool.
 * @param item_size The size of each item in the pool.
 * @param pool_width The width of the pool.
 * @return A pointer to the created generic pool.
 */
generic_pool_t *genericpoolCreateWithDefaultAllocatorAndCapacity(master_pool_t *mp, uint32_t item_size,
                                                                 uint32_t pool_width)
{
    return allocateGenericPool(mp, item_size, pool_width, poolDefaultAllocator, poolDefaultDeallocator);
}

/**
 * Destroys the generic pool and frees its resources.
 * @param pool The generic pool to destroy.
 */
void genericpoolDestroy(generic_pool_t *pool)
{
    for (uint32_t i = 0; i < pool->len; ++i)
    {
        pool->destroy_item_handle(pool, pool->available[i]);
    }
    memoryFree(pool);
}
