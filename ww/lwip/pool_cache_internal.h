#pragma once

#include "lwip/memp.h"
#include "pool_cache.h"
#include "watomic.h"

enum
{
#if WW_LWIP_POOL_CACHE_ENABLED
    kWwLwipPoolCacheRx = MEMP_POOL_LAST - MEMP_POOL_FIRST + 2,
#else
    kWwLwipPoolCacheRx = 0,
#endif
    kWwLwipPoolCacheCount = kWwLwipPoolCacheRx + 1
};

typedef struct ww_lwip_pool_cache_s
{
    struct ww_lwip_pool_cache_s *next; /* protected by SYS_ARCH_PROTECT */
    atomic_uintptr_t             heads[kWwLwipPoolCacheCount];
} ww_lwip_pool_cache_t;

void wwLwipPoolCacheInitialize(ww_lwip_pool_cache_t *cache);
void wwLwipPoolCacheDestroy(ww_lwip_pool_cache_t *cache);

/* NULL outside an entered engine. Only the owner publishes to its caches;
 * shared-pressure reclamation may atomically take an entire published list. */
ww_lwip_pool_cache_t *wwLwipEnginePoolCache(void);
