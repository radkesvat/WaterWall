#include "capacity_internal.h"

#include "engine.h"
#include "lwip/memp.h"
#include "lwip/stats.h"
#include "lwip/sys.h"
#include "pool_cache.h"
#include "wmem.h"

#include <assert.h>
#include <string.h>

static ww_lwip_capacity_config_t   configuration = {WW_LWIP_DEFAULT_MEMORY_BUDGET,
                                                    WW_LWIP_DEFAULT_TCP_FLOWS,
                                                    WW_LWIP_DEFAULT_UDP_FLOWS,
                                                    WW_LWIP_DEFAULT_TCP_LISTENERS,
                                                    WW_LWIP_DEFAULT_TCP_SEGMENTS,
                                                    WW_LWIP_DEFAULT_RX_WRAPPERS};
static ww_lwip_capacity_snapshot_t usage;
static bool                        initialized;

uint64_t wwLwipCapacityRecoveryHeadroom(void)
{
#if WW_LWIP_DYNAMIC_POOLS
    const uint64_t relative = configuration.memory_budget / 16U;
    return relative < 1024U * 1024U ? relative : 1024U * 1024U;
#else
    return 0;
#endif
}

#if WW_LWIP_DYNAMIC_POOLS
/* Static descriptors and their state survive shared runtime restarts. A custom
 * pool initialized through wonce remains registered after all slabs are freed. */
static ww_lwip_pool_state_t                  *registry;
static WW_LWIP_THREAD_LOCAL ww_lwip_engine_t *recovery_engine;

typedef struct ww_lwip_slab_s
{
    struct ww_lwip_slab_s  *next;
    struct ww_lwip_slab_s **previous;
    struct ww_lwip_slab_s  *available_next;
    struct ww_lwip_slab_s  *available_prev;
    ww_lwip_pool_state_t   *pool;
    void                   *free;
    size_t                  bytes;
    uint32_t                count;
    uint32_t                free_count;
    bool                    recovery;
} ww_lwip_slab_t;

typedef struct ww_lwip_item_s
{
    ww_lwip_slab_t *slab;
} ww_lwip_item_t;

enum
{
    kSlabBytes   = 64 * 1024,
    kSlabEntries = 256
};

static size_t itemPrefix(void)
{
    return LWIP_MEM_ALIGN_SIZE(sizeof(ww_lwip_item_t));
}

static uint32_t poolLimit(const ww_lwip_pool_state_t *state)
{
    const struct memp_desc *pool = state->descriptor;
    if (state->rx)
        return configuration.rx_wrappers;
    if (pool == memp_pools[MEMP_TCP_PCB])
        return configuration.tcp_flows;
    if (pool == memp_pools[MEMP_UDP_PCB])
        return configuration.udp_flows;
    if (pool == memp_pools[MEMP_TCP_PCB_LISTEN])
        return configuration.tcp_listeners;
    if (pool == memp_pools[MEMP_TCP_SEG])
        return configuration.tcp_segments;
    if (pool == memp_pools[MEMP_PBUF_POOL] || pool == memp_pools[MEMP_PBUF])
        return UINT32_MAX;
    for (unsigned i = MEMP_POOL_FIRST; i <= MEMP_POOL_LAST; ++i)
        if (pool == memp_pools[i])
            return UINT32_MAX;
    return pool->num;
}

static uint32_t recoverySlots(const ww_lwip_pool_state_t *state)
{
    if (! state->rx || state->limit <= 1)
        return 0;
    uint32_t count = state->limit / 16U;
    if (count == 0)
        count = 1;
    return count < 256U ? count : 256U;
}

static uint64_t ordinaryRemaining(void)
{
    return configuration.memory_budget - wwLwipCapacityRecoveryHeadroom() -
           (usage.reserved_bytes - usage.recovery_bytes);
}

static void removeAvailable(ww_lwip_pool_state_t *state, ww_lwip_slab_t *slab)
{
    if (slab->available_prev != NULL)
        slab->available_prev->available_next = slab->available_next;
    else
        state->available = slab->available_next;
    if (slab->available_next != NULL)
        slab->available_next->available_prev = slab->available_prev;
    slab->available_next = NULL;
    slab->available_prev = NULL;
}

static void prependAvailable(ww_lwip_pool_state_t *state, ww_lwip_slab_t *slab)
{
    slab->available_prev = NULL;
    slab->available_next = state->available;
    if (state->available != NULL)
        state->available->available_prev = slab;
    state->available = slab;
}

/* Shared protection is held. A cache drain transfers only free objects; it
 * never traverses another engine's live protocol state or invokes callbacks. */
static void reclaim(void)
{
    wwLwipPoolCacheReclaimAll();
    for (ww_lwip_pool_state_t *state = registry; state != NULL; state = state->next)
    {
        ww_lwip_slab_t **link = &state->slabs;
        while (*link != NULL)
        {
            ww_lwip_slab_t *slab = *link;
            if (slab->free_count != slab->count)
            {
                link = &slab->next;
                continue;
            }
            *link = slab->next;
            if (slab->next != NULL)
                slab->next->previous = link;
            removeAvailable(state, slab);
            state->allocated -= slab->count;
            state->reserved_bytes -= slab->bytes;
            usage.reserved_bytes -= slab->bytes;
            usage.reclaimed_bytes += slab->bytes;
            state->descriptor->stats->avail = state->allocated;
            memoryFree(slab);
        }
    }
}

static void recordReservation(size_t bytes)
{
    usage.reserved_bytes += bytes;
    if (usage.peak_reserved_bytes < usage.reserved_bytes)
        usage.peak_reserved_bytes = usage.reserved_bytes;
}

static bool reserveBytes(size_t bytes)
{
    if ((uint64_t) bytes > ordinaryRemaining())
        reclaim();
    if ((uint64_t) bytes > ordinaryRemaining())
        return false;
    recordReservation(bytes);
    return true;
}

static bool grow(ww_lwip_pool_state_t *state)
{
    assert(state->available == NULL);
    const uint32_t ordinary_limit     = state->limit - recoverySlots(state);
    const uint32_t ordinary_allocated = state->allocated - state->recovery_allocated;
    if (ordinary_allocated == ordinary_limit || state->allocated == state->limit)
    {
        /* Another owner may have returned objects to its cache since the
         * caller's first pressure pass. One finite pass makes those usable. */
        wwLwipPoolCacheReclaimAll();
        if (state->available != NULL)
            return true;
        ++state->entry_refusals;
        ++state->descriptor->stats->err;
        return false;
    }
    const size_t prefix   = itemPrefix();
    const size_t stride   = prefix + LWIP_MEM_ALIGN_SIZE(state->descriptor->size);
    const size_t overhead = sizeof(ww_lwip_slab_t) + MEM_ALIGNMENT - 1U;
    uint32_t     count    = (uint32_t) ((kSlabBytes - overhead) / stride);
    if (count == 0)
        count = 1;
    if (count > kSlabEntries)
        count = kSlabEntries;
    if (count > ordinary_limit - ordinary_allocated)
        count = ordinary_limit - ordinary_allocated;
    if (count > state->limit - state->allocated)
        count = state->limit - state->allocated;
    size_t bytes = overhead + (size_t) count * stride;
    if ((uint64_t) bytes > ordinaryRemaining())
    {
        reclaim();
        /* Reclamation may have returned a partial slab of this exact class. */
        if (state->available != NULL)
            return true;
        const uint64_t remaining = ordinaryRemaining();
        uint64_t       fitting   = remaining > overhead ? (remaining - overhead) / stride : 0;
        if (fitting < count)
            count = (uint32_t) fitting;
        if (count == 0)
        {
            ++usage.byte_refusals;
            ++state->byte_refusals;
            ++state->descriptor->stats->err;
            return false;
        }
        bytes = overhead + (size_t) count * stride;
    }
    recordReservation(bytes);
    /* Geometry is bounded above by one slab and was admitted before allocation.
     * WaterWall's allocator terminates on actual heap exhaustion. */
    ww_lwip_slab_t *slab = memoryAllocateZero(bytes);
    slab->pool           = state;
    slab->bytes          = bytes;
    slab->count          = count;
    slab->free_count     = count;
    uintptr_t start      = ((uintptr_t) (slab + 1) + MEM_ALIGNMENT - 1U) & ~(uintptr_t) (MEM_ALIGNMENT - 1U);
    for (uint32_t i = 0; i < count; ++i)
    {
        ww_lwip_item_t *header = (ww_lwip_item_t *) (start + (size_t) i * stride);
        header->slab           = slab;
        void *item             = (unsigned char *) header + prefix;
        *(void **) item        = slab->free;
        slab->free             = item;
    }
    slab->next     = state->slabs;
    slab->previous = &state->slabs;
    if (state->slabs != NULL)
        state->slabs->previous = &slab->next;
    state->slabs = slab;
    prependAvailable(state, slab);
    state->allocated += count;
    state->reserved_bytes += bytes;
    state->descriptor->stats->avail = state->allocated;
    return true;
}
#endif

void wwLwipCapacityConfigure(const ww_lwip_capacity_config_t *config)
{
    assert(! initialized && config != NULL);
    assert(config->memory_budget >= WW_LWIP_MIN_MEMORY_BUDGET && config->memory_budget <= SIZE_MAX);
    assert(config->tcp_flows != 0 && config->udp_flows != 0 && config->tcp_listeners != 0 &&
           config->tcp_segments != 0 && config->rx_wrappers != 0);
    configuration = *config;
}

void wwLwipCapacityInitialize(void)
{
    assert(! initialized);
    memset(&usage, 0, sizeof(usage));
    usage.recovery_headroom = wwLwipCapacityRecoveryHeadroom();
    initialized             = true;
#if WW_LWIP_DYNAMIC_POOLS
    for (ww_lwip_pool_state_t *state = registry; state != NULL; state = state->next)
    {
        assert(state->slabs == NULL && state->held == 0 && state->recovery_allocated == 0);
        state->limit          = poolLimit(state);
        state->peak_held      = 0;
        state->entry_refusals = 0;
        state->byte_refusals  = 0;
        memset(state->descriptor->stats, 0, sizeof(*state->descriptor->stats));
        state->descriptor->stats->name = state->descriptor->desc;
        ++usage.pool_count;
    }
#endif
}

void wwLwipCapacityCleanup(void)
{
    assert(initialized);
#if WW_LWIP_DYNAMIC_POOLS
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    reclaim();
    for (ww_lwip_pool_state_t *state = registry; state != NULL; state = state->next)
    {
        LWIP_ASSERT("all dynamic pool objects returned", state->held == 0 && state->allocated == 0);
    }
    LWIP_ASSERT("all external lwIP storage returned", usage.external_bytes == 0);
    LWIP_ASSERT("all recovery lwIP storage returned", usage.recovery_bytes == 0 && usage.external_recovery_bytes == 0);
    LWIP_ASSERT("all lwIP pool reservations released", usage.reserved_bytes == 0);
    SYS_ARCH_UNPROTECT(protection);
#endif
    initialized = false;
}

void wwLwipCapacityPoolInitialize(const struct memp_desc *pool)
{
#if WW_LWIP_DYNAMIC_POOLS
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    assert(initialized && pool->size >= sizeof(void *));
    ww_lwip_pool_state_t *state = pool->ww_pool;
    if (state->descriptor == NULL)
    {
        state->descriptor = pool;
        state->next       = registry;
        registry          = state;
        ++usage.pool_count;
    }
    else
    {
        assert(state->descriptor == pool && state->slabs == NULL && state->held == 0);
    }
    state->limit = poolLimit(state);
    memset(pool->stats, 0, sizeof(*pool->stats));
    pool->stats->name = pool->desc;
    SYS_ARCH_UNPROTECT(protection);
#else
    (void) pool;
#endif
}

void wwLwipCapacityRegisterRxPool(const struct memp_desc *pool)
{
#if WW_LWIP_DYNAMIC_POOLS
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    assert(initialized && pool->ww_pool->descriptor == pool && pool->ww_pool->held == 0);
    pool->ww_pool->rx    = true;
    pool->ww_pool->limit = configuration.rx_wrappers;
    SYS_ARCH_UNPROTECT(protection);
#else
    (void) pool;
#endif
}

void *wwLwipCapacityMalloc(const struct memp_desc *pool)
{
#if WW_LWIP_DYNAMIC_POOLS
    if (wwLwipCapacityRecoveryActive())
        return wwLwipCapacityMallocRecovery(pool);
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    assert(initialized && pool->ww_pool->descriptor == pool);
    ww_lwip_pool_state_t *state = pool->ww_pool;
    if (state->available == NULL && ! grow(state))
    {
        SYS_ARCH_UNPROTECT(protection);
        return NULL;
    }
    ww_lwip_slab_t *slab = state->available;
    void           *item = slab->free;
    slab->free           = *(void **) item;
    --slab->free_count;
    if (slab->free_count == 0)
        removeAvailable(state, slab);
    ++state->held;
    if (state->peak_held < state->held)
        state->peak_held = state->held;
    pool->stats->used = state->held;
    pool->stats->max  = state->peak_held;
    SYS_ARCH_UNPROTECT(protection);
    return item;
#else
    (void) pool;
    assert(false);
    return NULL;
#endif
}

void *wwLwipCapacityMallocRecovery(const struct memp_desc *pool)
{
#if WW_LWIP_DYNAMIC_POOLS
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    ww_lwip_pool_state_t *state = pool->ww_pool;
    assert(initialized && state->descriptor == pool);
    assert(state->rx || wwLwipCapacityRecoveryActive());
    const bool entry_full =
        state->allocated == state->limit || (state->rx && state->recovery_allocated == recoverySlots(state));
    if (entry_full)
    {
        ++state->entry_refusals;
        ++pool->stats->err;
        SYS_ARCH_UNPROTECT(protection);
        return NULL;
    }
    /* Single-entry recovery slabs avoid reserving an ordinary size-class batch
     * for one ACK. They never enter ordinary available lists or worker caches. */
    const size_t bytes = sizeof(ww_lwip_slab_t) + MEM_ALIGNMENT - 1U + itemPrefix() + LWIP_MEM_ALIGN_SIZE(pool->size);
    if ((uint64_t) bytes > wwLwipCapacityRecoveryHeadroom() - usage.recovery_bytes)
    {
        ++usage.recovery_refusals;
        ++usage.byte_refusals;
        ++state->byte_refusals;
        ++pool->stats->err;
        SYS_ARCH_UNPROTECT(protection);
        return NULL;
    }
    recordReservation(bytes);
    usage.recovery_bytes += bytes;
    ww_lwip_slab_t *slab = memoryAllocateZero(bytes);
    slab->pool           = state;
    slab->bytes          = bytes;
    slab->count          = 1;
    slab->recovery       = true;
    slab->next           = state->slabs;
    slab->previous       = &state->slabs;
    if (state->slabs != NULL)
        state->slabs->previous = &slab->next;
    state->slabs           = slab;
    const uintptr_t start  = ((uintptr_t) (slab + 1) + MEM_ALIGNMENT - 1U) & ~(uintptr_t) (MEM_ALIGNMENT - 1U);
    ww_lwip_item_t *header = (ww_lwip_item_t *) start;
    header->slab           = slab;
    ++state->allocated;
    ++state->recovery_allocated;
    ++state->held;
    if (state->peak_held < state->held)
        state->peak_held = state->held;
    state->reserved_bytes += bytes;
    pool->stats->avail = state->allocated;
    pool->stats->used  = state->held;
    pool->stats->max   = state->peak_held;
    SYS_ARCH_UNPROTECT(protection);
    return (unsigned char *) header + itemPrefix();
#else
    (void) pool;
    return NULL;
#endif
}

bool wwLwipCapacityIsRecovery(const void *item)
{
#if WW_LWIP_DYNAMIC_POOLS
    const ww_lwip_item_t *header = (const ww_lwip_item_t *) ((const unsigned char *) item - itemPrefix());
    return header->slab->recovery;
#else
    (void) item;
    return false;
#endif
}

bool wwLwipCapacityRecoveryActive(void)
{
#if WW_LWIP_DYNAMIC_POOLS
    assert(recovery_engine == NULL || recovery_engine == wwLwipEngineCurrent());
    return recovery_engine != NULL;
#else
    return false;
#endif
}

void wwLwipCapacityRecoveryBegin(void)
{
#if WW_LWIP_DYNAMIC_POOLS
    wwLwipEngineAssertCurrent();
    assert(recovery_engine == NULL);
    recovery_engine = wwLwipEngineCurrent();
#endif
}

void wwLwipCapacityRecoveryEnd(void)
{
#if WW_LWIP_DYNAMIC_POOLS
    assert(recovery_engine != NULL && recovery_engine == wwLwipEngineCurrent());
    recovery_engine = NULL;
#endif
}

void wwLwipCapacityFree(const struct memp_desc *pool, void *item)
{
#if WW_LWIP_DYNAMIC_POOLS
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    ww_lwip_pool_state_t *state  = pool->ww_pool;
    ww_lwip_item_t       *header = (ww_lwip_item_t *) ((unsigned char *) item - itemPrefix());
    ww_lwip_slab_t       *slab   = header->slab;
    LWIP_ASSERT("dynamic pool free matches its allocation",
                initialized && slab->pool == state && slab->free_count < slab->count && state->held != 0);
    if (slab->recovery)
    {
        LWIP_ASSERT("one exact recovery allocation", slab->count == 1 && state->recovery_allocated != 0);
        *slab->previous = slab->next;
        if (slab->next != NULL)
            slab->next->previous = slab->previous;
        --state->recovery_allocated;
        --state->allocated;
        --state->held;
        state->reserved_bytes -= slab->bytes;
        usage.reserved_bytes -= slab->bytes;
        usage.recovery_bytes -= slab->bytes;
        pool->stats->used  = state->held;
        pool->stats->avail = state->allocated;
        memoryFree(slab);
        SYS_ARCH_UNPROTECT(protection);
        return;
    }
    if (slab->free_count == 0)
        prependAvailable(state, slab);
    *(void **) item = slab->free;
    slab->free      = item;
    ++slab->free_count;
    --state->held;
    pool->stats->used = state->held;
    SYS_ARCH_UNPROTECT(protection);
#else
    (void) pool;
    (void) item;
    assert(false);
#endif
}

bool wwLwipCapacityHasFree(const struct memp_desc *pool)
{
#if WW_LWIP_DYNAMIC_POOLS
    return pool->ww_pool->available != NULL;
#else
    return *pool->tab != NULL;
#endif
}

bool wwLwipCapacityTryReserveExternal(size_t bytes)
{
#if WW_LWIP_DYNAMIC_POOLS
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    assert(initialized);
    const bool admitted = reserveBytes(bytes);
    if (admitted)
        usage.external_bytes += bytes;
    else
    {
        ++usage.byte_refusals;
        ++usage.external_refusals;
    }
    SYS_ARCH_UNPROTECT(protection);
    return admitted;
#else
    (void) bytes;
    return true;
#endif
}

void wwLwipCapacityReleaseExternal(size_t bytes)
{
#if WW_LWIP_DYNAMIC_POOLS
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    LWIP_ASSERT("balanced ordinary external lwIP reservation",
                initialized && usage.external_bytes - usage.external_recovery_bytes >= bytes);
    usage.external_bytes -= bytes;
    usage.reserved_bytes -= bytes;
    SYS_ARCH_UNPROTECT(protection);
#else
    (void) bytes;
#endif
}

bool wwLwipCapacityTryReserveExternalRecovery(size_t bytes)
{
#if WW_LWIP_DYNAMIC_POOLS
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    assert(initialized);
    const bool admitted = (uint64_t) bytes <= wwLwipCapacityRecoveryHeadroom() - usage.recovery_bytes;
    if (admitted)
    {
        recordReservation(bytes);
        usage.recovery_bytes += bytes;
        usage.external_bytes += bytes;
        usage.external_recovery_bytes += bytes;
    }
    else
    {
        ++usage.byte_refusals;
        ++usage.external_refusals;
        ++usage.recovery_refusals;
    }
    SYS_ARCH_UNPROTECT(protection);
    return admitted;
#else
    (void) bytes;
    return false;
#endif
}

void wwLwipCapacityReleaseExternalRecovery(size_t bytes)
{
#if WW_LWIP_DYNAMIC_POOLS
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    LWIP_ASSERT("balanced recovery external lwIP reservation", initialized && usage.external_recovery_bytes >= bytes);
    usage.reserved_bytes -= bytes;
    usage.recovery_bytes -= bytes;
    usage.external_bytes -= bytes;
    usage.external_recovery_bytes -= bytes;
    SYS_ARCH_UNPROTECT(protection);
#else
    (void) bytes;
#endif
}

size_t wwLwipCapacitySnapshot(ww_lwip_capacity_snapshot_t *snapshot, ww_lwip_pool_snapshot_t *pools, size_t capacity)
{
    assert(snapshot != NULL && (capacity == 0 || pools != NULL));
    SYS_ARCH_DECL_PROTECT(protection);
    SYS_ARCH_PROTECT(protection);
    *snapshot                   = usage;
    snapshot->config            = configuration;
    snapshot->recovery_headroom = wwLwipCapacityRecoveryHeadroom();
    snapshot->dynamic           = WW_LWIP_DYNAMIC_POOLS != 0;
    size_t count                = 0;
#if WW_LWIP_DYNAMIC_POOLS
    for (ww_lwip_pool_state_t *state = registry; state != NULL; state = state->next)
    {
        if (count < capacity)
        {
            pools[count] = (ww_lwip_pool_snapshot_t) {state->descriptor->desc,
                                                      state->descriptor->size,
                                                      state->limit,
                                                      state->allocated,
                                                      state->held,
                                                      state->peak_held,
                                                      state->entry_refusals,
                                                      state->byte_refusals,
                                                      state->reserved_bytes};
        }
        ++count;
    }
#else
    for (unsigned i = 0; i < MEMP_MAX; ++i)
    {
        const struct memp_desc *pool = memp_pools[i];
        if (count < capacity)
            pools[count] = (ww_lwip_pool_snapshot_t) {pool->desc,
                                                      pool->size,
                                                      pool->num,
                                                      pool->num,
                                                      pool->stats->used,
                                                      pool->stats->max,
                                                      0,
                                                      0,
                                                      (uint64_t) pool->num * (MEMP_SIZE + MEMP_ALIGN_SIZE(pool->size))};
        ++count;
    }
    snapshot->pool_count = count;
#endif
    SYS_ARCH_UNPROTECT(protection);
    return count;
}
