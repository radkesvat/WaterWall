#include "generic_pool.h"
#include "utils/mathutils.h"
#include "ww.h"
#ifdef POOL_DEBUG
#include "loggers/network_logger.h"
#endif
#define GENERIC_POOL_DEFAULT_WIDTH ((unsigned long) ((RAM_PROFILE)))

void poolReCharge(generic_pool_t *pool)
{
    const size_t increase = ((pool->cap - pool->len) < (pool->cap) / 2 ? (pool->cap - pool->len) : (pool->cap / 2));

    for (size_t i = pool->len; i < (pool->len + increase); i++)
    {
        pool->available[i] = pool->create_item_handle(pool);
    }
    pool->len += increase;
#if defined(DEBUG) && defined(POOL_DEBUG)
    hlogd("BufferPool: allocated %d new buffers, %zu are in use", increase, pool->in_use);
#endif
}

void poolShrink(generic_pool_t *pool)
{
    const size_t decrease = (pool->len < (pool->cap / 2) ? pool->len : (pool->cap / 2));

    for (size_t i = pool->len - decrease; i < pool->len; i++)
    {
        pool->destroy_item_handle(pool, pool->available[i]);
    }
    pool->len -= decrease;

#if defined(DEBUG) && defined(POOL_DEBUG)
    hlogd("BufferPool: freed %d buffers, %zu are in use", decrease, pool->in_use);
#endif
#ifdef OS_LINUX
    // malloc_trim(0);
#endif
}

static void poolFirstCharge(generic_pool_t *pool)
{
    pool->len = pool->cap / 2;
    for (size_t i = 0; i < pool->len; i++)
    {
        pool->available[i] = pool->create_item_handle(pool);
    }
}

static generic_pool_t *allocateGenericPool(unsigned int item_size, unsigned int pool_width,
                                           PoolItemCreateHandle create_h, PoolItemDestroyHandle destroy_h)
{

    pool_width = (unsigned long) pow(2, floor(log2((double) (max(16, (ssize_t) pool_width)))));
    // half of the pool is used, other half is free at startup
    pool_width = 2 * pool_width;

    const unsigned long container_len = pool_width * sizeof(pool_item_t *);
    generic_pool_t     *pool_ptr      = globalMalloc(sizeof(generic_pool_t) + container_len);
#ifdef DEBUG
    memset(pool_ptr, 0xEB, sizeof(generic_pool_t) + container_len);
#endif
    generic_pool_t pool = {.cap                 = pool_width,
                           .free_threshould     = max(pool_width / 2, (pool_width * 2) / 3),
                           .item_size           = item_size,
                           .create_item_handle  = create_h,
                           .destroy_item_handle = destroy_h};

    memcpy(pool_ptr, &pool, sizeof(generic_pool_t));
    poolFirstCharge(pool_ptr);
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

generic_pool_t *newGenericPool(PoolItemCreateHandle create_h, PoolItemDestroyHandle destroy_h)
{
    return allocateGenericPool(0, GENERIC_POOL_DEFAULT_WIDTH, create_h, destroy_h);
}
generic_pool_t *newGenericPoolWithCap(unsigned int pool_width, PoolItemCreateHandle create_h,
                                      PoolItemDestroyHandle destroy_h)
{
    return allocateGenericPool(0, pool_width, create_h, destroy_h);
}

generic_pool_t *newGenericPoolDefaultAllocator(unsigned int item_size)
{
    return allocateGenericPool(item_size, GENERIC_POOL_DEFAULT_WIDTH, poolDefaultAllocator, poolDefaultDeallocator);
}

generic_pool_t *newGenericPoolDefaultAllocatorWithCap(unsigned int item_size, unsigned int pool_width)
{
    return allocateGenericPool(item_size, pool_width, poolDefaultAllocator, poolDefaultDeallocator);
}
