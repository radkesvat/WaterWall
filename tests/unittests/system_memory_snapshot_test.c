#include "global_state.h"
#include "wsysinfo.h"
#include "wthread.h"

typedef struct memory_test_provider_s
{
    atomic_ullong now_ms;
    atomic_uint   calls;
    atomic_int    result;
    bool          alternate;
} memory_test_provider_t;

typedef struct memory_reader_s
{
    atomic_bool failed;
    atomic_bool stop;
} memory_reader_t;

typedef struct tuple_provider_s
{
    uint64_t                 now_ms;
    system_memory_snapshot_t tuple;
} tuple_provider_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static uint64_t fakeNow(void *userdata)
{
    memory_test_provider_t *provider = userdata;
    return atomicLoadU64Relaxed(&provider->now_ms);
}

static system_memory_provider_result_t fakeProvider(void *userdata, system_memory_snapshot_t *snapshot)
{
    memory_test_provider_t *provider = userdata;
    atomicIncRelaxed(&provider->calls);
    const system_memory_provider_result_t result =
        (system_memory_provider_result_t) atomicLoadRelaxed(&provider->result);
    if (result != kSystemMemoryProviderOk)
    {
        return result;
    }

    const bool low_available         = provider->alternate && ((atomicLoadRelaxed(&provider->calls) & 1U) != 0);
    snapshot->host_total_bytes       = 1000000;
    snapshot->host_available_bytes   = low_available ? 200000 : 800000;
    snapshot->cgroup_limited         = true;
    snapshot->cgroup_limit_bytes     = 500000;
    snapshot->cgroup_current_bytes   = low_available ? 400000 : 100000;
    snapshot->cgroup_available_bytes = low_available ? 100000 : 400000;
    return kSystemMemoryProviderOk;
}

static WTHREAD_ROUTINE(memoryReaderMain)
{
    memory_reader_t *reader = userdata;
    while (! atomicLoadRelaxed(&reader->stop))
    {
        system_memory_snapshot_t              snapshot;
        const system_memory_snapshot_status_t status = systemMemorySnapshotGet(&snapshot);
        if (status == kSystemMemorySnapshotUnavailable)
        {
            continue;
        }
        if (status != kSystemMemorySnapshotFresh)
        {
            atomicStoreRelaxed(&reader->failed, true);
            break;
        }
        const bool high_tuple = snapshot.host_available_bytes == 800000 && snapshot.cgroup_current_bytes == 100000 &&
                                snapshot.cgroup_available_bytes == 400000 &&
                                snapshot.effective_available_bytes == 400000;
        const bool low_tuple = snapshot.host_available_bytes == 200000 && snapshot.cgroup_current_bytes == 400000 &&
                               snapshot.cgroup_available_bytes == 100000 &&
                               snapshot.effective_available_bytes == 100000;
        if (! high_tuple && ! low_tuple)
        {
            atomicStoreRelaxed(&reader->failed, true);
            break;
        }
    }
    return 0;
}

static uint64_t tupleNow(void *userdata)
{
    return ((tuple_provider_t *) userdata)->now_ms;
}

static system_memory_provider_result_t tupleProvider(void *userdata, system_memory_snapshot_t *snapshot)
{
    *snapshot = ((tuple_provider_t *) userdata)->tuple;
    return kSystemMemoryProviderOk;
}

static void requireTupleStatus(tuple_provider_t *provider, system_memory_snapshot_status_t expected,
                               system_memory_snapshot_t *snapshot, const char *message)
{
    system_load_state_t state = {0};
    require(systemLoadSamplerTryInit(&state), "failed to initialize tuple-invariant sampler");
    systemLoadSamplerSetMemoryTestHooks(&state, tupleProvider, tupleNow, provider);
    discard              systemLoadSamplerUpdate(&state);
    system_load_state_t *saved_state = GSTATE.system_load;
    GSTATE.system_load               = &state;
    require(systemMemorySnapshotGet(snapshot) == expected, message);
    GSTATE.system_load = saved_state;
    systemLoadSamplerDestroy(&state);
}

static void testSnapshotTupleInvariants(void)
{
    tuple_provider_t provider = {
        .now_ms = 100,
        .tuple  = {.host_total_bytes       = 1000,
                   .host_available_bytes   = 800,
                   .cgroup_limited         = true,
                   .cgroup_current_bytes   = 900,
                   .cgroup_limit_bytes     = 1000,
                   .cgroup_available_bytes = 10},
    };
    system_memory_snapshot_t snapshot;
    requireTupleStatus(
        &provider, kSystemMemorySnapshotFresh, &snapshot, "valid split pressure/headroom tuple was rejected");
    require(snapshot.cgroup_used_basis_points == 9000 && snapshot.cgroup_available_bytes == 10 &&
                snapshot.effective_available_bytes == 10,
            "split pressure/headroom tuple was finalized incorrectly");

    provider.tuple.cgroup_available_bytes = 101;
    requireTupleStatus(&provider,
                       kSystemMemorySnapshotUnavailable,
                       &snapshot,
                       "headroom greater than diagnostic remaining bytes was accepted");
    provider.tuple.cgroup_current_bytes   = 100;
    provider.tuple.cgroup_limit_bytes     = 200;
    provider.tuple.cgroup_available_bytes = 0;
    requireTupleStatus(&provider,
                       kSystemMemorySnapshotUnavailable,
                       &snapshot,
                       "zero headroom without a 100 percent diagnostic level was accepted");
    provider.tuple.cgroup_current_bytes   = 201;
    provider.tuple.cgroup_available_bytes = 1;
    requireTupleStatus(
        &provider, kSystemMemorySnapshotUnavailable, &snapshot, "current-above-limit tuple retained nonzero headroom");
    provider.tuple.cgroup_available_bytes = 0;
    requireTupleStatus(
        &provider, kSystemMemorySnapshotFresh, &snapshot, "current-above-limit zero-headroom tuple was rejected");
    require(snapshot.cgroup_used_basis_points == 10000 && snapshot.effective_available_bytes == 0,
            "current-above-limit tuple did not saturate pressure and headroom");

    provider.tuple.cgroup_limited         = false;
    provider.tuple.cgroup_current_bytes   = 123;
    provider.tuple.cgroup_limit_bytes     = 456;
    provider.tuple.cgroup_available_bytes = 78;
    requireTupleStatus(&provider,
                       kSystemMemorySnapshotFresh,
                       &snapshot,
                       "host-only tuple with provider diagnostic residue was rejected instead of cleared");
    require(snapshot.cgroup_current_bytes == 0 && snapshot.cgroup_limit_bytes == 0 &&
                snapshot.cgroup_available_bytes == 0 && snapshot.cgroup_used_basis_points == 0,
            "host-only tuple retained cgroup diagnostic fields");
}

int main(void)
{
    uint64_t total     = 0;
    uint64_t available = 0;
    require(
        systemMemoryParseLinuxMeminfo("MemFree: 1 kB\nMemAvailable: 2048 kB\nMemTotal: 4096 kB\n", &total, &available),
        "valid MemTotal/MemAvailable input was rejected");
    require(total == 4096U * 1024U && available == 2048U * 1024U, "meminfo kB conversion produced the wrong bytes");
    require(! systemMemoryParseLinuxMeminfo("MemTotal: 4096 MB\nMemAvailable: 2048 kB\n", &total, &available),
            "malformed meminfo unit was accepted");
    require(! systemMemoryParseLinuxMeminfo("MemTotal: 4096 kB\n", &total, &available),
            "missing MemAvailable was accepted");

    uint64_t parsed    = 0;
    bool     unbounded = false;
    require(systemMemoryParseUnsignedValue("max\n", true, &parsed, &unbounded) && unbounded,
            "cgroup v2 max value was rejected");
    require(systemMemoryParseUnsignedValue("18446744073709551615\n", false, &parsed, &unbounded) &&
                parsed == UINT64_MAX && ! unbounded,
            "maximum cgroup integer was parsed incorrectly");
    require(! systemMemoryParseUnsignedValue("18446744073709551616", false, &parsed, &unbounded),
            "overflowing cgroup integer was accepted");
    system_load_state_t production_state = {0};
    require(systemLoadSamplerTryInit(&production_state), "failed to initialize production memory sampler");
    system_load_state_t *saved_state = GSTATE.system_load;
    GSTATE.system_load               = &production_state;
    system_memory_snapshot_t production_snapshot;
#ifdef OS_WIN
    require(systemMemorySnapshotGet(&production_snapshot) == kSystemMemorySnapshotFresh &&
                production_snapshot.host_total_bytes > 0 &&
                production_snapshot.host_available_bytes <= production_snapshot.host_total_bytes &&
                ! production_snapshot.cgroup_limited,
            "Windows production GlobalMemoryStatusEx snapshot was not published coherently");
#elif defined(OS_DARWIN)
    require(systemMemorySnapshotGet(&production_snapshot) == kSystemMemorySnapshotUnsupported,
            "Darwin production memory provider did not report unsupported");
#else
    discard production_snapshot;
#endif
    GSTATE.system_load = saved_state;
    systemLoadSamplerDestroy(&production_state);

    testSnapshotTupleInvariants();

    system_load_state_t state = {0};
    require(systemLoadSamplerTryInit(&state), "failed to initialize memory sampler fixture");

    memory_test_provider_t provider = {0};
    atomicStoreU64Relaxed(&provider.now_ms, 100);
    atomicStoreRelaxed(&provider.result, kSystemMemoryProviderOk);
    systemLoadSamplerSetMemoryTestHooks(&state, fakeProvider, fakeNow, &provider);

    saved_state        = GSTATE.system_load;
    GSTATE.system_load = &state;

    require(systemLoadSamplerUpdate(&state), "initial fake memory snapshot was not published");
    const unsigned int       calls_after_update = (unsigned int) atomicLoadRelaxed(&provider.calls);
    system_memory_snapshot_t snapshot;
    require(systemMemorySnapshotGet(&snapshot) == kSystemMemorySnapshotFresh,
            "initial synchronous memory snapshot was not fresh");
    require(snapshot.host_used_basis_points == 2000 && snapshot.cgroup_used_basis_points == 2000 &&
                snapshot.cgroup_available_bytes == 400000 && snapshot.effective_available_bytes == 400000,
            "host/cgroup effective snapshot calculation is wrong");
    require((unsigned int) atomicLoadRelaxed(&provider.calls) == calls_after_update,
            "cached memory getter invoked the provider");

    atomicStoreU64Relaxed(&provider.now_ms, 1100);
    require(systemMemorySnapshotGet(&snapshot) == kSystemMemorySnapshotFresh,
            "snapshot was stale at the inclusive one-second boundary");
    atomicStoreU64Relaxed(&provider.now_ms, 1101);
    require(systemMemorySnapshotGet(&snapshot) == kSystemMemorySnapshotStale,
            "snapshot remained fresh beyond one second");

    atomicStoreU64Relaxed(&provider.now_ms, 2000);
    atomicStoreRelaxed(&provider.result, kSystemMemoryProviderOk);
    require(systemLoadSamplerUpdate(&state), "fresh snapshot recovery failed");
    atomicStoreRelaxed(&provider.result, kSystemMemoryProviderUnavailable);
    discard systemLoadSamplerUpdate(&state);
    require(systemMemorySnapshotGet(&snapshot) == kSystemMemorySnapshotFresh,
            "transient provider error discarded a still-fresh last-valid snapshot");
    atomicStoreU64Relaxed(&provider.now_ms, 3000);
    require(systemMemorySnapshotGet(&snapshot) == kSystemMemorySnapshotFresh,
            "last-valid snapshot was stale at the inclusive one-second boundary");
    atomicStoreU64Relaxed(&provider.now_ms, 3001);
    require(systemMemorySnapshotGet(&snapshot) == kSystemMemorySnapshotStale,
            "last-valid snapshot remained fresh beyond its one-second deadline");

    atomicStoreRelaxed(&provider.result, kSystemMemoryProviderUnsupported);
    systemLoadSamplerSetMemoryTestHooks(&state, fakeProvider, fakeNow, &provider);
    discard systemLoadSamplerUpdate(&state);
    require(systemMemorySnapshotGet(&snapshot) == kSystemMemorySnapshotUnsupported,
            "unsupported provider did not produce explicit unsupported status");

    atomicStoreRelaxed(&provider.result, kSystemMemoryProviderUnavailable);
    systemLoadSamplerSetMemoryTestHooks(&state, fakeProvider, fakeNow, &provider);
    discard systemLoadSamplerUpdate(&state);
    require(systemMemorySnapshotGet(&snapshot) == kSystemMemorySnapshotUnavailable,
            "unavailable provider did not produce explicit unavailable status");

    atomicStoreRelaxed(&provider.result, kSystemMemoryProviderOk);
    provider.alternate = true;
    systemLoadSamplerSetMemoryTestHooks(&state, fakeProvider, fakeNow, &provider);
    require(systemLoadSamplerUpdate(&state), "failed to seed concurrent memory publication");

    memory_reader_t reader = {0};
    wthread_t       thread;
    require(threadCreate(&thread, memoryReaderMain, &reader) == kWThreadErrorNone,
            "failed to start concurrent memory snapshot reader");
    for (unsigned int i = 0; i < 10000; ++i)
    {
        require(systemLoadSamplerUpdate(&state), "concurrent memory publication failed");
    }
    atomicStoreRelaxed(&reader.stop, true);
    require(threadJoin(thread) == 0, "failed to join concurrent memory snapshot reader");
    require(! atomicLoadRelaxed(&reader.failed), "reader observed a torn memory snapshot");

    GSTATE.system_load = saved_state;
    systemLoadSamplerDestroy(&state);

    printf("system_memory_snapshot_test: all cases passed\n");
    return 0;
}
