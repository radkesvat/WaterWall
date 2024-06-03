#include "generic_pool.h"
#include "utils/mathutils.h"
#include "ww.h"

#define GENERIC_POOL_DEFAULT_WIDTH ((unsigned long) ((16 * ram_profile)))

extern void         poolReCharge(generic_pool_t *pool);
extern void         poolShrink(generic_pool_t *pool);
extern pool_item_t *popPoolItem(generic_pool_t *pool);
extern void         reusePoolItem(generic_pool_t *pool, pool_item_t *b);

static void poolFirstCharge(generic_pool_t *pool)
{
    pool->len = pool->cap / 2;
    for (size_t i = 0; i < pool->len; i++)
    {
        pool->available[i] = pool->create_item_handle(pool);
    }
}

static generic_pool_t *allocateGenericPool(unsigned long pool_width, PoolItemCreateHandle create_h,
                                           PoolItemDestroyHandle destroy_h)
{

    pool_width = (unsigned long) pow(2, floor(log2((double) (max(16, (ssize_t) pool_width)))));
    // half of the pool is used, other half is free at startup
    pool_width = 2 * pool_width;

    const unsigned long container_len = pool_width * sizeof(pool_item_t *);
    generic_pool_t     *pool          = malloc(sizeof(generic_pool_t) + container_len);
#ifdef DEBUG
    memset(pool, 0xEE, sizeof(generic_pool_t) + container_len);
#endif
    memset(pool, 0, sizeof(generic_pool_t));
    pool->cap                 = pool_width;
    pool->free_threshould     = (pool->cap * 2) / 3;
    pool->create_item_handle  = create_h;
    pool->destroy_item_handle = destroy_h;
    poolFirstCharge(pool);
    return pool;
}

generic_pool_t *newGenericPool(PoolItemCreateHandle create_h, PoolItemDestroyHandle destroy_h)
{
    return allocateGenericPool(GENERIC_POOL_DEFAULT_WIDTH, create_h, destroy_h);
}
generic_pool_t *newGenericPoolWithSize(unsigned long pool_width, PoolItemCreateHandle create_h,
                                       PoolItemDestroyHandle destroy_h)
{
    return allocateGenericPool(pool_width, create_h, destroy_h);
}
