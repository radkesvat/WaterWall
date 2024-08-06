#include "generic_pool.h"
#include "utils/mathutils.h"
#include "ww.h"
#ifdef POOL_DEBUG
#include "loggers/network_logger.h"
#endif
#define GENERIC_POOL_DEFAULT_WIDTH ((unsigned long) ((RAM_PROFILE)))

static master_pool_item_t *poolCreateItemHandle(struct master_pool_s *pool, void *userdata)
{
    (void) pool;
    generic_pool_t *gpool = userdata;
    if (gpool->item_size == 0)
    {
        return gpool->create_item_handle(gpool);
    }
    return globalMalloc(gpool->item_size);
}

static void poolDestroyItemHandle(struct master_pool_s *pool, master_pool_item_t *item, void *userdata)
{
    (void) pool;
    generic_pool_t *gpool = userdata;
    if (gpool->item_size == 0)
    {
        gpool->destroy_item_handle(gpool, item);
    }
    globalFree(item);
}

void poolReCharge(generic_pool_t *pool)
{
    const size_t increase = min((pool->cap - pool->len), (pool->cap) / 2);

    popMasterPoolItems(pool->mp, (void const **) &(pool->available[pool->len]), increase);

    pool->len += increase;
#if defined(DEBUG) && defined(POOL_DEBUG)
    hlogd("BufferPool: allocated %d new buffers, %zu are in use", increase, pool->in_use);
#endif
}

void poolShrink(generic_pool_t *pool)
{
    const size_t decrease = (pool->len < (pool->cap / 2) ? pool->len : (pool->cap / 2));

    reuseMasterPoolItems(pool->mp, &(pool->available[pool->len - decrease]), decrease);

    pool->len -= decrease;

#if defined(DEBUG) && defined(POOL_DEBUG)
    hlogd("BufferPool: freed %d buffers, %zu are in use", decrease, pool->in_use);
#endif
}

static void poolFirstCharge(generic_pool_t *pool)
{
    poolReCharge(pool);
}

static generic_pool_t *allocateGenericPool(struct master_pool_s *mp, unsigned int item_size, unsigned int pool_width,
                                           PoolItemCreateHandle create_h, PoolItemDestroyHandle destroy_h)
{

    pool_width = (max(1, pool_width) + 15) & ~0x0F;

    // half of the pool is used, other half is free at startup
    pool_width = 2 * pool_width;

    const unsigned long container_len = pool_width * sizeof(pool_item_t *);
    generic_pool_t     *pool_ptr      = globalMalloc(sizeof(generic_pool_t) + container_len);
#ifdef DEBUG
    memset(pool_ptr, 0xEB, sizeof(generic_pool_t) + container_len);
#endif
    *pool_ptr = (generic_pool_t) {.cap                 = pool_width,
                                  .free_threshold      = max(pool_width / 2, (pool_width * 2) / 3),
                                  .item_size           = item_size,
                                  .mp                  = mp,
                                  .create_item_handle  = create_h,
                                  .destroy_item_handle = destroy_h};
    installMasterPoolAllocCallbacks(pool_ptr->mp, pool_ptr,poolCreateItemHandle, poolDestroyItemHandle);
    // poolFirstCharge(pool_ptr);
    return pool_ptr;
}

static pool_item_t *poolDefaultAllocator(struct generic_pool_s *pool)
{
    return globalMalloc(pool->item_size);
}

static void poolDefaultDeallocator(struct generic_pool_s *pool, pool_item_t *item)
{
    (void) pool;
    globalFree(item);
}

generic_pool_t *newGenericPool(struct master_pool_s *mp, PoolItemCreateHandle create_h, PoolItemDestroyHandle destroy_h)
{
    return allocateGenericPool(mp, 0, GENERIC_POOL_DEFAULT_WIDTH, create_h, destroy_h);
}

generic_pool_t *newGenericPoolWithCap(struct master_pool_s *mp, unsigned int pool_width, PoolItemCreateHandle create_h,
                                      PoolItemDestroyHandle destroy_h)
{
    return allocateGenericPool(mp, 0, pool_width, create_h, destroy_h);
}

generic_pool_t *newGenericPoolDefaultAllocator(struct master_pool_s *mp, unsigned int item_size)
{
    return allocateGenericPool(mp, item_size, GENERIC_POOL_DEFAULT_WIDTH, poolDefaultAllocator, poolDefaultDeallocator);
}

generic_pool_t *newGenericPoolDefaultAllocatorWithCap(struct master_pool_s *mp, unsigned int item_size,
                                                      unsigned int pool_width)
{
    return allocateGenericPool(mp, item_size, pool_width, poolDefaultAllocator, poolDefaultDeallocator);
}
