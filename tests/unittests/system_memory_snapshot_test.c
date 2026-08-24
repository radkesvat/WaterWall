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

typedef struct memory_timer_fixture_s
{
    SystemLoadSamplerTestTimerCallback callback;
    void                              *timer_userdata;
    uint32_t                           timeout_ms;
    uint32_t                           repeat;
    unsigned int                       add_calls;
    unsigned int                       set_calls;
    unsigned int                       get_calls;
    unsigned int                       delete_calls;
    bool                               fail_add;
    ww_max_align_t                     timer_storage;
} memory_timer_fixture_t;

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

static wtimer_t *fakeTimerAdd(void *userdata, wloop_t *loop, SystemLoadSamplerTestTimerCallback callback,
                              void *callback_userdata, uint32_t timeout_ms, uint32_t repeat)
{
    discard                 loop;
    memory_timer_fixture_t *fixture = userdata;
    fixture->add_calls++;
    fixture->callback = callback;
    discard callback_userdata;
    fixture->timeout_ms = timeout_ms;
    fixture->repeat     = repeat;
    return fixture->fail_add ? NULL : (wtimer_t *) (void *) &fixture->timer_storage;
}

static void fakeTimerSetUserdata(void *userdata, wtimer_t *timer, void *timer_userdata)
{
    memory_timer_fixture_t *fixture = userdata;
    require(timer == (wtimer_t *) (void *) &fixture->timer_storage, "timer userdata was set on an unknown timer");
    fixture->set_calls++;
    fixture->timer_userdata = timer_userdata;
}

static void *fakeTimerGetUserdata(void *userdata, wtimer_t *timer)
{
    memory_timer_fixture_t *fixture = userdata;
    require(timer == (wtimer_t *) (void *) &fixture->timer_storage, "timer userdata was read from an unknown timer");
    fixture->get_calls++;
    return fixture->timer_userdata;
}

static void fakeTimerDelete(void *userdata, wtimer_t *timer)
{
    memory_timer_fixture_t *fixture = userdata;
    require(timer == (wtimer_t *) (void *) &fixture->timer_storage, "an unknown timer was deleted");
    fixture->delete_calls++;
}

static void fakeTimerDispatch(memory_timer_fixture_t *fixture)
{
    require(fixture->callback != NULL, "fake timer has no captured callback");
    void *timer_userdata = fakeTimerGetUserdata(fixture, (wtimer_t *) (void *) &fixture->timer_storage);
    fixture->callback(timer_userdata);
}

static const system_load_sampler_timer_test_ops_t timer_ops = {
    .add          = fakeTimerAdd,
    .set_userdata = fakeTimerSetUserdata,
    .get_userdata = fakeTimerGetUserdata,
    .delete_timer = fakeTimerDelete,
};

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
    require(systemLoadSamplerTryInitWithMemoryTestHooks(&state, tupleProvider, tupleNow, provider, NULL, NULL),
            "failed to initialize tuple-invariant sampler");
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

static void testSamplerLifecycle(void)
{
    memory_test_provider_t provider = {0};
    atomicStoreU64Relaxed(&provider.now_ms, 100);
    atomicStoreRelaxed(&provider.result, kSystemMemoryProviderOk);
    memory_timer_fixture_t timer = {0};
    system_load_state_t    state = {0};
    require(systemLoadSamplerTryInitWithMemoryTestHooks(&state, fakeProvider, fakeNow, &provider, &timer_ops, &timer),
            "test-hook sampler initialization failed");
    require(atomicLoadRelaxed(&provider.calls) == 1U,
            "sampler initialization did not synchronously publish before returning");
    require(systemLoadSamplerStart(&state, (wloop_t *) &timer), "deterministic sampler timer did not start");
    require(timer.add_calls == 1U && timer.set_calls == 1U && timer.get_calls == 1U &&
                timer.timeout_ms == SYSTEM_LOAD_SAMPLER_INTERVAL_MS && timer.repeat == INFINITE,
            "sampler timer did not request the established 500 ms repeating cadence");
    require(timer.callback != NULL, "sampler timer callback root was not captured");
    fakeTimerDispatch(&timer);
    fakeTimerDispatch(&timer);
    require(atomicLoadRelaxed(&provider.calls) == 3U, "deterministic timer advancement invoked the wrong updates");
    systemLoadSamplerStop(&state);
    require(timer.set_calls == 2U && timer.timer_userdata == NULL && timer.delete_calls == 1U,
            "sampler stop did not clear userdata and delete its timer");
    fakeTimerDispatch(&timer);
    require(atomicLoadRelaxed(&provider.calls) == 3U, "stopped sampler retained a live callback root");
    systemLoadSamplerDestroy(&state);
    systemLoadSamplerDestroy(&state);

    memory_timer_fixture_t destroy_timer = {0};
    system_load_state_t    destroy_state = {0};
    require(systemLoadSamplerTryInitWithMemoryTestHooks(
                &destroy_state, fakeProvider, fakeNow, &provider, &timer_ops, &destroy_timer),
            "active-destroy sampler initialization failed");
    require(systemLoadSamplerStart(&destroy_state, (wloop_t *) &destroy_timer),
            "active-destroy sampler timer did not start");
    const unsigned int calls_before_destroy = (unsigned int) atomicLoadRelaxed(&provider.calls);
    systemLoadSamplerDestroy(&destroy_state);
    require(destroy_timer.set_calls == 2U && destroy_timer.timer_userdata == NULL && destroy_timer.delete_calls == 1U,
            "destroying an active sampler did not clear and delete its timer exactly once");
    fakeTimerDispatch(&destroy_timer);
    require((unsigned int) atomicLoadRelaxed(&provider.calls) == calls_before_destroy,
            "destroyed sampler retained a live callback root");
    systemLoadSamplerDestroy(&destroy_state);
    require(destroy_timer.set_calls == 2U && destroy_timer.delete_calls == 1U,
            "second sampler destruction repeated timer cleanup");

    memory_timer_fixture_t failed_timer = {.fail_add = true};
    system_load_state_t    failed_state = {0};
    require(systemLoadSamplerTryInitWithMemoryTestHooks(
                &failed_state, fakeProvider, fakeNow, &provider, &timer_ops, &failed_timer),
            "timer-failure sampler initialization failed");
    require(! systemLoadSamplerStart(&failed_state, (wloop_t *) &failed_timer) && failed_state.timer == NULL &&
                failed_timer.add_calls == 1U && failed_timer.set_calls == 0U && failed_timer.delete_calls == 0U,
            "timer construction failure retained or partially published a callback root");
    systemLoadSamplerDestroy(&failed_state);
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

    testSamplerLifecycle();
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
