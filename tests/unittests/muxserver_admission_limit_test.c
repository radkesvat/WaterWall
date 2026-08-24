#include "MuxServer/structure.h"

#include "wthread.h"

typedef struct admission_memory_provider_s
{
    atomic_ullong                   now_ms;
    uint64_t                        host_total;
    uint64_t                        host_available;
    uint64_t                        cgroup_limit;
    uint64_t                        cgroup_current;
    system_memory_provider_result_t result;
    bool                            cgroup_limited;
} admission_memory_provider_t;

typedef struct reservation_thread_s
{
    muxserver_tstate_t *ts;
    uint32_t            ceiling;
    atomic_uint        *successes;
} reservation_thread_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static uint64_t admissionNow(void *userdata)
{
    admission_memory_provider_t *provider = userdata;
    return atomicLoadU64Relaxed(&provider->now_ms);
}

static system_memory_provider_result_t admissionProvider(void *userdata, system_memory_snapshot_t *snapshot)
{
    admission_memory_provider_t *provider = userdata;
    if (provider->result != kSystemMemoryProviderOk)
    {
        return provider->result;
    }
    snapshot->host_total_bytes     = provider->host_total;
    snapshot->host_available_bytes = provider->host_available;
    snapshot->cgroup_limited       = provider->cgroup_limited;
    snapshot->cgroup_limit_bytes   = provider->cgroup_limit;
    snapshot->cgroup_current_bytes = provider->cgroup_current;
    snapshot->cgroup_available_bytes =
        provider->cgroup_current >= provider->cgroup_limit ? 0 : provider->cgroup_limit - provider->cgroup_current;
    return kSystemMemoryProviderOk;
}

static WTHREAD_ROUTINE(reservationThreadMain)
{
    reservation_thread_t *thread = userdata;
    if (muxserverTryReserveLiveChildSlot(thread->ts, thread->ceiling))
    {
        atomicIncRelaxed(thread->successes);
    }
    return 0;
}

static void testAdmissionDefaults(void)
{
    static const uint32_t reserves[] = {
        32U * 1024U * 1024U,
        77U * 1024U * 1024U,
        122U * 1024U * 1024U,
        166U * 1024U * 1024U,
        211U * 1024U * 1024U,
        256U * 1024U * 1024U,
    };
    static const uint32_t fallbacks[] = {4096, 5677, 7258, 8838, 10419, 12000};
    static const uint32_t profiles[]  = {kRamProfileS1Memory,
                                         kRamProfileS2Memory,
                                         kRamProfileM1Memory,
                                         kRamProfileM2Memory,
                                         kRamProfileL1Memory,
                                         kRamProfileL2Memory};

    for (size_t i = 0; i < ARRAY_SIZE(profiles); ++i)
    {
        const mux_admission_defaults_t defaults = muxGetDefaultAdmissionLimits(profiles[i]);
        require(defaults.memory_reserve == reserves[i], "RAM-profile admission reserve drifted");
        require(defaults.fallback_live_children == fallbacks[i], "RAM-profile fallback ceiling drifted");
    }
}

static void testPlatformProductionFallback(void)
{
#ifdef OS_DARWIN
    system_load_state_t sampler = {0};
    require(systemLoadSamplerTryInit(&sampler), "failed to initialize Darwin production memory sampler");
    system_load_state_t *saved_sampler = GSTATE.system_load;
    GSTATE.system_load                 = &sampler;
    muxserver_tstate_t *ts             = memoryAllocateZero(sizeof(*ts));
    require(ts != NULL, "failed to allocate Darwin fallback admission state");
    ts->max_live_children                 = 10;
    ts->memory_fallback_max_live_children = 3;
    muxserver_memory_admission_t decision = muxserverEvaluateMemoryAdmission(ts);
    require(decision.snapshot_status == kSystemMemorySnapshotUnsupported && decision.permits_memory &&
                decision.effective_ceiling == 3,
            "Darwin unsupported production sampler did not select the conservative fallback ceiling");
    memoryFree(ts);
    GSTATE.system_load = saved_sampler;
    systemLoadSamplerDestroy(&sampler);
#endif
}

static void testMemoryHysteresis(void)
{
    system_load_state_t sampler = {0};
    require(systemLoadSamplerTryInit(&sampler), "failed to initialize admission memory fixture");

    admission_memory_provider_t provider = {
        .host_total     = 1000000,
        .host_available = 300000,
        .cgroup_limit   = 500000,
        .cgroup_current = 350000,
        .result         = kSystemMemoryProviderOk,
        .cgroup_limited = true,
    };
    atomicStoreU64Relaxed(&provider.now_ms, 100);
    systemLoadSamplerSetMemoryTestHooks(&sampler, admissionProvider, admissionNow, &provider);
    system_load_state_t *saved_sampler = GSTATE.system_load;
    GSTATE.system_load                 = &sampler;

    muxserver_tstate_t *ts = memoryAllocateZero(sizeof(*ts));
    require(ts != NULL, "failed to allocate MuxServer admission state");
    ts->max_live_children                 = 10;
    ts->memory_fallback_max_live_children = 3;
    ts->memory_high_watermark_percent     = 85;
    ts->memory_low_watermark_percent      = 75;
    ts->memory_reserve                    = 0;
    atomicStoreRelaxed(&ts->live_children_count, 0);
    atomicStoreU64Relaxed(&ts->memory_admission_state, 0);

    require(systemLoadSamplerUpdate(&sampler), "failed to publish low-pressure snapshot");
    muxserver_memory_admission_t decision = muxserverEvaluateMemoryAdmission(ts);
    require(decision.permits_memory && ! decision.gate_closed && decision.effective_ceiling == 10,
            "low-pressure fresh snapshot did not admit at the hard ceiling");

    provider.host_available = 150000; // exactly 85% used
    atomicStoreU64Relaxed(&provider.now_ms, 200);
    require(systemLoadSamplerUpdate(&sampler), "failed to publish high-pressure snapshot");
    decision = muxserverEvaluateMemoryAdmission(ts);
    require(! decision.permits_memory && decision.gate_closed && decision.gate_transitioned,
            "high watermark did not close admission");

    provider.host_available = 200000; // between high and low
    atomicStoreU64Relaxed(&provider.now_ms, 300);
    require(systemLoadSamplerUpdate(&sampler), "failed to publish hysteresis-band snapshot");
    decision = muxserverEvaluateMemoryAdmission(ts);
    require(! decision.permits_memory && decision.gate_closed, "hysteresis band reopened a pressure-closed gate");

    provider.host_available = 300000;
    provider.cgroup_current = 125000; // both sources exactly 75% or lower
    atomicStoreU64Relaxed(&provider.now_ms, 400);
    require(systemLoadSamplerUpdate(&sampler), "failed to publish recovery snapshot");
    decision = muxserverEvaluateMemoryAdmission(ts);
    require(decision.permits_memory && ! decision.gate_closed && decision.gate_transitioned,
            "low watermark did not reopen admission");

    ts->memory_reserve      = 150000;
    provider.host_available = 500000;
    provider.cgroup_current = 350000; // finite cgroup remaining equals reserve
    atomicStoreU64Relaxed(&provider.now_ms, 500);
    require(systemLoadSamplerUpdate(&sampler), "failed to publish reserve-boundary snapshot");
    decision = muxserverEvaluateMemoryAdmission(ts);
    require(! decision.permits_memory && decision.gate_closed,
            "effective available bytes at reserve did not close admission");

    atomicStoreU64Relaxed(&provider.now_ms, 1601);
    decision = muxserverEvaluateMemoryAdmission(ts);
    require(! decision.permits_memory && decision.gate_closed, "stale data reopened a gate closed by fresh pressure");

    atomicStoreU64Relaxed(&ts->memory_admission_state, 0);
    decision = muxserverEvaluateMemoryAdmission(ts);
    require(decision.permits_memory && decision.effective_ceiling == 3,
            "stale open gate did not select conservative fallback ceiling");

    GSTATE.system_load = saved_sampler;
    systemLoadSamplerDestroy(&sampler);
    memoryFree(ts);
}

static void testConcurrentReservations(void)
{
    enum
    {
        kThreads = 32,
        kCeiling = 5,
    };
    muxserver_tstate_t *ts = memoryAllocateZero(sizeof(*ts));
    require(ts != NULL, "failed to allocate reservation state");
    ts->max_live_children          = 100;
    atomic_uint          successes = 0;
    wthread_t            threads[kThreads];
    reservation_thread_t arguments[kThreads];

    for (size_t i = 0; i < kThreads; ++i)
    {
        arguments[i] = (reservation_thread_t) {.ts = ts, .ceiling = kCeiling, .successes = &successes};
        require(threadCreate(&threads[i], reservationThreadMain, &arguments[i]) == kWThreadErrorNone,
                "failed to create reservation racer");
    }
    for (size_t i = 0; i < kThreads; ++i)
    {
        require(threadJoin(threads[i]) == 0, "failed to join reservation racer");
    }

    require((unsigned int) atomicLoadRelaxed(&successes) == kCeiling &&
                (unsigned int) atomicLoadRelaxed(&ts->live_children_count) == kCeiling,
            "concurrent reservations overran or underfilled the effective ceiling");
    for (unsigned int i = 0; i < kCeiling; ++i)
    {
        muxserverReleaseLiveChildSlot(ts);
    }
    require(atomicLoadRelaxed(&ts->live_children_count) == 0,
            "aggregate reservation releases did not restore capacity");
    memoryFree(ts);
}

static void testCidIndexesAndRejectionBucket(void)
{
    enum
    {
        kChildren = 4096,
    };
    muxserver_parent_state_t server_parent_state = {.child_map = muxserver_child_map_t_init()};
    muxserver_lstate_t       server_parent       = {.parent_state = &server_parent_state};
    muxserver_lstate_t      *server_children     = memoryAllocateZero(sizeof(*server_children) * kChildren);
    require(server_children != NULL, "failed to allocate server CID fixture");

    for (uint32_t i = 0; i < kChildren; ++i)
    {
        server_children[i].is_child      = true;
        server_children[i].connection_id = (i * 65537U) + 17U;
        muxserverJoinConnection(&server_parent, &server_children[i]);
    }
    require(server_parent.children_count == kChildren &&
                muxserver_child_map_t_size(&server_parent_state.child_map) == kChildren,
            "server map/list/count join invariant failed");
    for (uint32_t i = 0; i < kChildren; ++i)
    {
        require(muxserverFindChildByConnectionId(&server_parent, server_children[i].connection_id) ==
                    &server_children[i],
                "server CID index resolved the wrong child");
    }
    for (uint32_t i = 1; i < kChildren; i += 2)
    {
        muxserverLeaveConnection(&server_children[i]);
    }
    for (uint32_t i = 0; i < kChildren; i += 2)
    {
        muxserverLeaveConnection(&server_children[i]);
    }
    require(server_parent.children_count == 0 && server_parent.child_next == NULL &&
                muxserver_child_map_t_size(&server_parent_state.child_map) == 0,
            "server arbitrary removals broke map/list/count agreement");

    server_parent_state.rejection_bucket.tokens = kMuxServerRejectedOpenBurst;
    for (unsigned int i = 0; i < kMuxServerRejectedOpenBurst; ++i)
    {
        require(muxserverConsumeRejectedOpenToken(&server_parent, 100), "rejection burst depleted too early");
    }
    require(! muxserverConsumeRejectedOpenToken(&server_parent, 100), "rejection burst exceeded capacity");
    for (unsigned int i = 0; i < kMuxServerRejectedOpenRefillPerSecond; ++i)
    {
        require(muxserverConsumeRejectedOpenToken(&server_parent, 1100), "rejection refill depleted too early");
    }
    require(! muxserverConsumeRejectedOpenToken(&server_parent, 1100), "rejection refill exceeded 64 tokens");

    muxserver_child_map_t_drop(&server_parent_state.child_map);
    memoryFree(server_children);
}

int main(void)
{
    testAdmissionDefaults();
    testPlatformProductionFallback();
    testMemoryHysteresis();
    testConcurrentReservations();
    testCidIndexesAndRejectionBucket();
    printf("muxserver_admission_limit_test: all cases passed\n");
    return 0;
}
