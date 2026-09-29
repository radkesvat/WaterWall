#include "pool_cache_internal.h"

#include "lwip/sys.h"
#include <assert.h>

#if WW_LWIP_POOL_CACHE_ENABLED
enum
{
    kCacheRefill = 8,
    kCacheLimit  = 256
};

/* Free items carry the list metadata in their unused payload. Backing storage
 * stays in the original process-wide pools until shared runtime finalization. */
typedef struct cached_item_s
{
    struct cached_item_s *next;
    unsigned              count;
} cached_item_t;

static ww_lwip_pool_cache_t *caches;
static atomic_uintptr_t      rx_pool;

static int cacheIndex(const struct memp_desc *pool)
{
    if (pool == memp_pools[MEMP_TCP_SEG])
        return 0;
    for (unsigned i = MEMP_POOL_FIRST; i <= MEMP_POOL_LAST; ++i)
        if (pool == memp_pools[i])
            return (int) (i - MEMP_POOL_FIRST + 1);
    if (pool == (const struct memp_desc *) atomicLoadExplicit(&rx_pool, memory_order_acquire))
        return kWwLwipPoolCacheRx;
    return -1;
}

static const struct memp_desc *cachePool(unsigned index)
{
    if (index == 0)
        return memp_pools[MEMP_TCP_SEG];
    if (index == kWwLwipPoolCacheRx)
        return (const struct memp_desc *) atomicLoadExplicit(&rx_pool, memory_order_acquire);
    return memp_pools[MEMP_POOL_FIRST + index - 1];
}

static cached_item_t *take(ww_lwip_pool_cache_t *cache, unsigned index)
{
    return (cached_item_t *) atomicExchangeExplicit(&cache->heads[index], 0, memory_order_acq_rel);
}

static void publish(ww_lwip_pool_cache_t *cache, unsigned index, cached_item_t *head)
{
    atomicStoreExplicit(&cache->heads[index], (uintptr_t) head, memory_order_release);
}

static cached_item_t *prepend(void *item, cached_item_t *head)
{
    cached_item_t *node = item;
    node->next          = head;
    node->count         = head != NULL ? head->count + 1 : 1;
    assert(node->count <= kCacheLimit);
    return node;
}

/* Caller holds shared protection. No destructor or protocol callback runs here. */
static void returnList(const struct memp_desc *pool, cached_item_t *head)
{
    while (head != NULL)
    {
        cached_item_t *next = head->next;
        wwLwipMempFreeShared(pool, head);
        head = next;
    }
}

void *wwLwipPoolCacheMalloc(const struct memp_desc *pool)
{
    const int index = cacheIndex(pool);
    if (index < 0)
        return wwLwipMempMallocShared(pool);
    assert(pool->size >= sizeof(cached_item_t));
    ww_lwip_pool_cache_t *cache = wwLwipEnginePoolCache();
    if (cache != NULL)
    {
        cached_item_t *head = take(cache, (unsigned) index);
        if (head != NULL)
        {
            publish(cache, (unsigned) index, head->next);
            return head;
        }
    }

    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    if (*pool->tab == NULL)
    {
        /* Registry lifetime is protected here. Atomic detach transfers only
         * free allocator storage; it never reads another engine's live objects.
         * An owner temporarily holding a detached list will publish it before
         * its allocation/free returns. An idle owner's list is reclaimable. */
        for (ww_lwip_pool_cache_t *other = caches; other != NULL; other = other->next)
            returnList(pool, take(other, (unsigned) index));
    }
    void *item = wwLwipMempMallocShared(pool);
    if (item != NULL && cache != NULL)
    {
        cached_item_t *head = NULL;
        for (unsigned i = 1; i < kCacheRefill && *pool->tab != NULL; ++i)
            head = prepend(wwLwipMempMallocShared(pool), head);
        publish(cache, (unsigned) index, head);
    }
    SYS_ARCH_UNPROTECT(protection);
    return item;
}

void wwLwipPoolCacheFree(const struct memp_desc *pool, void *item)
{
    const int             index = cacheIndex(pool);
    ww_lwip_pool_cache_t *cache = wwLwipEnginePoolCache();
    if (index < 0 || cache == NULL)
    {
        wwLwipMempFreeShared(pool, item);
        return;
    }
    cached_item_t *head = take(cache, (unsigned) index);
    if (head != NULL && head->count == kCacheLimit)
    {
        SYS_ARCH_DECL_PROTECT(protection);
        SYS_ARCH_PROTECT(protection);
        returnList(pool, head);
        SYS_ARCH_UNPROTECT(protection);
        head = NULL;
    }
    publish(cache, (unsigned) index, prepend(item, head));
}
#endif

void wwLwipPoolCacheRegisterRxPool(const struct memp_desc *pool)
{
#if WW_LWIP_POOL_CACHE_ENABLED
    assert(pool->size >= sizeof(cached_item_t));
    const uintptr_t previous = atomicExchangeExplicit(&rx_pool, (uintptr_t) pool, memory_order_acq_rel);
    assert(previous == 0 || previous == (uintptr_t) pool);
    (void) previous;
#else
    (void) pool;
#endif
}

void wwLwipPoolCacheInitialize(ww_lwip_pool_cache_t *cache)
{
    for (unsigned i = 0; i < kWwLwipPoolCacheCount; ++i)
        atomic_init(&cache->heads[i], 0);
#if WW_LWIP_POOL_CACHE_ENABLED
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    cache->next = caches;
    caches      = cache;
    SYS_ARCH_UNPROTECT(protection);
#endif
}

void wwLwipPoolCacheDestroy(ww_lwip_pool_cache_t *cache)
{
#if WW_LWIP_POOL_CACHE_ENABLED
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    ww_lwip_pool_cache_t **link = &caches;
    while (*link != cache)
    {
        assert(*link != NULL);
        link = &(*link)->next;
    }
    *link = cache->next;
    for (unsigned i = 0; i < kWwLwipPoolCacheCount; ++i)
        returnList(cachePool(i), take(cache, i));
    SYS_ARCH_UNPROTECT(protection);
#else
    (void) cache;
#endif
}
