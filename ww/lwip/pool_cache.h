#pragma once

#include "lwip/opt.h"

struct memp_desc;

/* Diagnostic allocator modes retain their original per-operation checks. */
#if defined(LWIP_HOOK_MEMP_AVAILABLE) || defined(LWIP_HOOK_FILENAME)
#define WW_LWIP_POOL_CACHE_ENABLED 0
#else
#define WW_LWIP_POOL_CACHE_ENABLED                                                                                     \
    (WW_LWIP_WORKER_ENGINES && MEM_USE_POOLS && ! MEMP_MEM_MALLOC && ! MEMP_OVERFLOW_CHECK && ! MEMP_SANITY_CHECK)
#endif

void wwLwipPoolCacheRegisterRxPool(const struct memp_desc *pool);

#if WW_LWIP_POOL_CACHE_ENABLED
void *wwLwipPoolCacheMalloc(const struct memp_desc *pool);
void  wwLwipPoolCacheFree(const struct memp_desc *pool, void *item);

/* The pinned memp implementation supplies these uncached primitives. They keep
 * its shared freelists, capacity, statistics and nullable exhaustion behavior. */
void *wwLwipMempMallocShared(const struct memp_desc *pool);
void  wwLwipMempFreeShared(const struct memp_desc *pool, void *item);
#endif
