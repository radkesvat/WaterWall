/*
 * Covers: demand-grown lwIP pools, shared byte/object admission and cache pressure.
 * Setup: production allocator and worker engines, isolated owner/runtime boundary.
 * Checks: allocation above 65535 objects, exact entry/byte refusal, payload
 * integrity, reclaim across size classes and owner caches, foreign frees and
 * shared runtime restart with a once-registered custom receive pool.
 * Limits: allocator correctness, not application throughput or total process RSS.
 * CTest: waterwall.lwip_dynamic_pools_unit (Debug and Release).
 */
#include "capacity.h"
#include "fixtures/lwip/lwip_engine_test_runtime.h"
#include "pool_cache.h"

#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/stats.h"

#if ! WW_LWIP_DYNAMIC_POOLS
#error "This fixture requires the production demand-grown allocator"
#endif

LWIP_MEMPOOL_DECLARE(CAPACITY_RX_TEST, 11, 64, "Capacity RX fixture")

static ww_lwip_capacity_config_t config = {128ULL * 1024ULL * 1024ULL, 65540, 17, 7, 70000, 7};

static ww_lwip_pool_snapshot_t poolSnapshot(const struct memp_desc *pool)
{
    ww_lwip_capacity_snapshot_t summary;
    ww_lwip_pool_snapshot_t     pools[128];
    const size_t                count = wwLwipCapacitySnapshot(&summary, pools, 128);
    CHECK(count <= 128);
    CHECK(summary.reserved_bytes <= summary.config.memory_budget);
    uint64_t                reserved = summary.external_bytes;
    bool                    found    = false;
    ww_lwip_pool_snapshot_t result   = {0};
    for (size_t i = 0; i < count; ++i)
    {
        reserved += pools[i].reserved_bytes;
        CHECK(pools[i].held <= pools[i].allocated && pools[i].allocated <= pools[i].limit);
        if (pools[i].name == pool->desc)
        {
            result = pools[i];
            found  = true;
        }
    }
    CHECK(reserved == summary.reserved_bytes && found);
    return result;
}

static void wideObjectCounts(void)
{
    wwLwipCapacityConfigure(&config);
    wwLwipEngineSharedInit();
    LWIP_MEMPOOL_INIT(CAPACITY_RX_TEST);
    wwLwipPoolCacheRegisterRxPool(&memp_CAPACITY_RX_TEST);

    void **items = calloc(config.tcp_flows, sizeof(*items));
    CHECK(items != NULL);
    for (uint32_t i = 0; i < config.tcp_flows; ++i)
    {
        items[i] = memp_malloc(MEMP_TCP_PCB);
        CHECK(items[i] != NULL && (uintptr_t) items[i] % MEM_ALIGNMENT == 0);
        memset(items[i], (int) (i % 251U), memp_pools[MEMP_TCP_PCB]->size);
    }
    CHECK(memp_malloc(MEMP_TCP_PCB) == NULL);
    ww_lwip_pool_snapshot_t state = poolSnapshot(memp_pools[MEMP_TCP_PCB]);
    CHECK(state.held == config.tcp_flows && state.peak_held == config.tcp_flows);
    CHECK(state.entry_refusals == 1 && state.byte_refusals == 0);
    CHECK(memp_pools[MEMP_TCP_PCB]->stats->used == config.tcp_flows);
    for (uint32_t i = 0; i < config.tcp_flows; ++i)
    {
        const unsigned char *bytes = items[i];
        for (unsigned j = 0; j < memp_pools[MEMP_TCP_PCB]->size; ++j)
            CHECK(bytes[j] == i % 251U);
        memp_free(MEMP_TCP_PCB, items[i]);
    }
    free(items);

    void *wrappers[7];
    for (unsigned i = 0; i < 6; ++i)
    {
        wrappers[i] = LWIP_MEMPOOL_ALLOC(CAPACITY_RX_TEST);
        CHECK(wrappers[i] != NULL);
    }
    CHECK(LWIP_MEMPOOL_ALLOC(CAPACITY_RX_TEST) == NULL);
    wrappers[6] = wwLwipCapacityMallocRecovery(&memp_CAPACITY_RX_TEST);
    CHECK(wrappers[6] != NULL && wwLwipCapacityMallocRecovery(&memp_CAPACITY_RX_TEST) == NULL);
    CHECK(poolSnapshot(&memp_CAPACITY_RX_TEST).limit == 7);
    for (unsigned i = 0; i < 7; ++i)
        LWIP_MEMPOOL_FREE(CAPACITY_RX_TEST, wrappers[i]);
    wwLwipEngineSharedCleanup();
}

static void classPressureAndRestart(void)
{
    config.memory_budget = WW_LWIP_MIN_MEMORY_BUDGET;
    config.tcp_flows     = 17;
    wwLwipCapacityConfigure(&config);
    wwLwipEngineSharedInit();
    /* The RX pool's process-once registration survives shared finalization. */
    void *wrapper = LWIP_MEMPOOL_ALLOC(CAPACITY_RX_TEST);
    CHECK(wrapper != NULL);
    LWIP_MEMPOOL_FREE(CAPACITY_RX_TEST, wrapper);

    owner                    = 0;
    owner_loop               = (const struct wloop_s *) (uintptr_t) 1;
    ww_lwip_engine_t *engine = wwLwipEngineCreate((uint8_t) owner, (struct wloop_s *) owner_loop);
    CHECK(engine != NULL);
    ww_lwip_engine_t *previous;
    CHECK(wwLwipEngineEnter(engine, &previous));

    void  *large[128];
    size_t large_count = 0;
    while (large_count < 128 && (large[large_count] = mem_malloc(16000)) != NULL)
    {
        memset(large[large_count], 0xa5, 16000);
        ++large_count;
    }
    CHECK(large_count > 2 && large_count < 128);
    for (size_t i = 0; i < large_count; ++i)
    {
        CHECK(((unsigned char *) large[i])[15999] == 0xa5);
        mem_free(large[i]);
    }
    /* Large blocks now reside in this engine's cache. A different size class
     * must reclaim them and empty backing slabs instead of staying starved. */
    void  *small[8192];
    size_t small_count = 0;
    while (small_count < 8192 && (small[small_count] = mem_malloc(200)) != NULL)
    {
        memset(small[small_count], 0x5a, 200);
        ++small_count;
    }
    CHECK(small_count > 1024 && small_count < 8192);
    CHECK(poolSnapshot(memp_pools[MEMP_POOL_16384]).allocated == 0);
    for (size_t i = 0; i < small_count; ++i)
    {
        CHECK(((unsigned char *) small[i])[0] == 0x5a && ((unsigned char *) small[i])[199] == 0x5a);
        mem_free(small[i]);
    }
    wwLwipEngineLeave(engine, previous);
    wwLwipEngineDestroy(engine);
    owner      = 255;
    owner_loop = NULL;

    const size_t recovery = (size_t) wwLwipCapacityRecoveryHeadroom();
    const size_t ordinary = (size_t) config.memory_budget - recovery;
    CHECK(wwLwipCapacityTryReserveExternal(ordinary));
    CHECK(wwLwipCapacityTryReserveExternalRecovery(recovery));
    ww_lwip_capacity_snapshot_t summary;
    wwLwipCapacitySnapshot(&summary, NULL, 0);
    CHECK(summary.reserved_bytes == config.memory_budget && summary.external_bytes == config.memory_budget);
    CHECK(summary.reclaimed_bytes > 0);
    CHECK(! wwLwipCapacityTryReserveExternal(1));
    CHECK(! wwLwipCapacityTryReserveExternalRecovery(1));
    CHECK(mem_malloc(200) == NULL);
    wwLwipCapacityReleaseExternalRecovery(recovery);
    CHECK(mem_malloc(200) == NULL); /* Ordinary data cannot consume the idle reserve. */
    wwLwipCapacityReleaseExternal(ordinary);
    CHECK(! wwLwipCapacityTryReserveExternal(SIZE_MAX));
    CHECK(mem_malloc(SIZE_MAX) == NULL);
    void *recovered = mem_malloc(200);
    CHECK(recovered != NULL);
    mem_free(recovered);
    wwLwipEngineSharedCleanup();
}

static pthread_barrier_t rendezvous;
static void             *handoff[2];

static void meet(void)
{
    const int result = pthread_barrier_wait(&rendezvous);
    CHECK(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD);
}

static void *concurrentOwner(void *argument)
{
    owner                    = (unsigned) (uintptr_t) argument;
    owner_loop               = (const struct wloop_s *) (uintptr_t) (owner + 1U);
    ww_lwip_engine_t *engine = wwLwipEngineCreate((uint8_t) owner, (struct wloop_s *) owner_loop);
    CHECK(engine != NULL);
    ww_lwip_engine_t *previous;
    CHECK(wwLwipEngineEnter(engine, &previous));
    for (unsigned round = 0; round < 100; ++round)
    {
        void    *items[12];
        unsigned count = 0;
        while (count < 12 && (items[count] = memp_malloc(MEMP_TCP_SEG)) != NULL)
        {
            memset(items[count], (int) (owner + 1U), memp_pools[MEMP_TCP_SEG]->size);
            ++count;
        }
        meet();
        for (unsigned i = 0; i < count; ++i)
        {
            const unsigned char *bytes = items[i];
            for (unsigned j = 0; j < memp_pools[MEMP_TCP_SEG]->size; ++j)
                CHECK(bytes[j] == owner + 1U);
            memp_free(MEMP_TCP_SEG, items[i]);
        }
        meet();
    }
    handoff[owner] = memp_malloc(MEMP_TCP_PCB);
    CHECK(handoff[owner] != NULL);
    memset(handoff[owner], (int) (owner + 10U), memp_pools[MEMP_TCP_PCB]->size);
    meet();
    CHECK(((unsigned char *) handoff[1U - owner])[0] == 11U - owner);
    memp_free(MEMP_TCP_PCB, handoff[1U - owner]);
    meet();
    wwLwipEngineLeave(engine, previous);
    wwLwipEngineDestroy(engine);
    return NULL;
}

static void concurrentPressure(void)
{
    config.tcp_segments = 17;
    wwLwipCapacityConfigure(&config);
    wwLwipEngineSharedInit();
    CHECK(pthread_barrier_init(&rendezvous, NULL, 2) == 0);
    pthread_t threads[2];
    for (uintptr_t i = 0; i < 2; ++i)
        CHECK(pthread_create(&threads[i], NULL, concurrentOwner, (void *) i) == 0);
    for (unsigned i = 0; i < 2; ++i)
        CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(pthread_barrier_destroy(&rendezvous) == 0);
    const ww_lwip_pool_snapshot_t state = poolSnapshot(memp_pools[MEMP_TCP_SEG]);
    CHECK(state.limit == 17 && state.held == 0 && state.peak_held <= 17 && state.entry_refusals != 0);
    wwLwipEngineSharedCleanup();
}

int main(void)
{
    wideObjectCounts();
    classPressureAndRestart();
    concurrentPressure();
    puts("dynamic lwIP object/byte limits, wide accounting, cache reclamation and restart passed");
    return 0;
}
