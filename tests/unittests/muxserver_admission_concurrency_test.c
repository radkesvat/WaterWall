#include "MuxServer/structure.h"

#include "wthread.h"

enum
{
    kRaceWorkers       = 2,
    kRaceOpensPerRound = 4,
    kRaceBufferSize    = 4096,
};

typedef struct admission_race_fixture_s admission_race_fixture_t;

typedef struct admission_race_task_s
{
    admission_race_fixture_t *fixture;
    wid_t                     wid;
} admission_race_task_t;

typedef enum admission_race_command_e
{
    kAdmissionRaceCommandNone,
    kAdmissionRaceCommandOpen,
    kAdmissionRaceCommandDestroyOne,
    kAdmissionRaceCommandCleanupAndExit,
} admission_race_command_t;

typedef struct race_memory_provider_s
{
    atomic_ullong                   now_ms;
    system_memory_provider_result_t result;
} race_memory_provider_t;

struct admission_race_fixture_s
{
    master_pool_t             *large_masters[kRaceWorkers];
    master_pool_t             *small_masters[kRaceWorkers];
    master_pool_t             *wios_master;
    master_pool_t             *parent_master;
    buffer_pool_t             *pools[kRaceWorkers];
    threadsafe_generic_pool_t *wios_pools[kRaceWorkers];
    wloop_t                   *loops[kRaceWorkers];
    worker_t                   workers[kRaceWorkers];
    generic_pool_t            *parent_pools[kRaceWorkers];
    tunnel_chain_t            *chain;
    tunnel_t                  *prev;
    tunnel_t                  *mux;
    tunnel_t                  *next;
    line_t                    *parents[kRaceWorkers];
    mux_cid_t                  current_cid[kRaceWorkers];
    mux_cid_t                  expected_child_close_cid[kRaceWorkers];
    atomic_uint                admitted[kRaceWorkers];
    atomic_uint                rejected[kRaceWorkers];
    atomic_uint                finished[kRaceWorkers];
    atomic_uint                timer_counts[kRaceWorkers];
    atomic_uint                ready;
    atomic_uint                command_generation;
    atomic_uint                command_completed;
    atomic_uint                command;
    atomic_uint                destroy_wid;
    atomic_uint                opens_per_worker;
    atomic_uint                round;
    wthread_t                  threads[kRaceWorkers];
    admission_race_task_t      tasks[kRaceWorkers];
};

static admission_race_fixture_t *g_race_fixture;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        fflush(stderr);
        exit(1);
    }
}

static uint64_t raceMemoryNow(void *userdata)
{
    return atomicLoadU64Relaxed(&((race_memory_provider_t *) userdata)->now_ms);
}

static system_memory_provider_result_t raceMemoryProvider(void *userdata, system_memory_snapshot_t *snapshot)
{
    race_memory_provider_t *provider = userdata;
    if (provider->result != kSystemMemoryProviderOk)
    {
        return provider->result;
    }
    snapshot->host_total_bytes     = 1000;
    snapshot->host_available_bytes = 900;
    snapshot->cgroup_limited       = false;
    return kSystemMemoryProviderOk;
}

static void writeOpenFrame(uint8_t *out, mux_cid_t cid)
{
    out[0] = 0;
    out[1] = 0;
    out[2] = kMuxFlagOpen;
    out[3] = 0;
    out[4] = (uint8_t) ((cid >> 24U) & 0xFFU);
    out[5] = (uint8_t) ((cid >> 16U) & 0xFFU);
    out[6] = (uint8_t) ((cid >> 8U) & 0xFFU);
    out[7] = (uint8_t) (cid & 0xFFU);
}

static mux_cid_t readFrameCid(const uint8_t *bytes)
{
    return ((mux_cid_t) bytes[4] << 24U) | ((mux_cid_t) bytes[5] << 16U) | ((mux_cid_t) bytes[6] << 8U) |
           (mux_cid_t) bytes[7];
}

static void racePrevEst(tunnel_t *prev, line_t *parent_l)
{
    admission_race_fixture_t *fixture = g_race_fixture;
    require(fixture != NULL && prev == fixture->prev && lineIsOnCurrentEventWorker(parent_l),
            "race parent Est reached the wrong previous tunnel or worker");
}

static void racePrevPayload(tunnel_t *prev, line_t *parent_l, sbuf_t *buf)
{
    admission_race_fixture_t *fixture = g_race_fixture;
    require(fixture != NULL && prev == fixture->prev, "race rejection reached the wrong previous tunnel");
    const wid_t wid = lineGetWID(parent_l);
    require(wid < kRaceWorkers && lineIsOnCurrentEventWorker(parent_l),
            "race rejection ran outside its parent owner worker");
    require(sbufGetLength(buf) == kMuxFrameLength, "race rejection emitted the wrong frame length");
    const uint8_t  *bytes      = sbufGetRawPtr(buf);
    const mux_cid_t actual_cid = readFrameCid(bytes);
    require(bytes[0] == 0 && bytes[1] == 0 && bytes[2] == kMuxFlagClose, "race parser emitted malformed Close bytes");
    if (fixture->expected_child_close_cid[wid] != 0)
    {
        require(actual_cid == fixture->expected_child_close_cid[wid],
                "explicit child destruction emitted Close for the wrong CID");
        fixture->expected_child_close_cid[wid] = 0;
        lineReuseBuffer(parent_l, buf);
        return;
    }
    require(actual_cid == fixture->current_cid[wid], "race rejection did not emit one matching Close");
    atomicIncRelaxed(&fixture->rejected[wid]);
    lineReuseBuffer(parent_l, buf);
}

static void raceNextInit(tunnel_t *next, line_t *child_l)
{
    admission_race_fixture_t *fixture = g_race_fixture;
    require(fixture != NULL && next == fixture->next && lineIsOnCurrentEventWorker(child_l),
            "admitted race child Init ran on the wrong worker");
    atomicIncRelaxed(&fixture->admitted[lineGetWID(child_l)]);
}

static void raceNextFinish(tunnel_t *next, line_t *child_l)
{
    admission_race_fixture_t *fixture = g_race_fixture;
    require(fixture != NULL && next == fixture->next && lineIsOnCurrentEventWorker(child_l),
            "race child Finish ran on the wrong worker");
    atomicIncRelaxed(&fixture->finished[lineGetWID(child_l)]);
}

static void raceSendOpen(admission_race_fixture_t *fixture, wid_t wid, mux_cid_t cid)
{
    fixture->current_cid[wid] = cid;
    sbuf_t *frame             = bufferpoolGetLargeBuffer(fixture->pools[wid]);
    sbufSetLength(frame, kMuxFrameLength);
    writeOpenFrame(sbufGetMutablePtr(frame), cid);
    muxserverTunnelUpStreamPayload(fixture->mux, fixture->parents[wid], frame);
}

static void racePublishTimerCount(admission_race_fixture_t *fixture, wid_t wid)
{
    muxserver_tstate_t *ts    = tunnelGetState(fixture->mux);
    const uint32_t      count = ts->worker_states[wid].child_idle_table == NULL
                                    ? 0
                                    : (uint32_t) localidletableGetItemCount(ts->worker_states[wid].child_idle_table);
    atomicStoreExplicit(&fixture->timer_counts[wid], count, memory_order_release);
}

static WTHREAD_ROUTINE(admissionRaceMain)
{
    admission_race_task_t    *task    = userdata;
    admission_race_fixture_t *fixture = task->fixture;
    const wid_t               wid     = task->wid;
    testWorkerBindWID(wid);
    fixture->parents[wid] = lineCreate(fixture->parent_pools, wid);
    muxserverTunnelUpStreamInit(fixture->mux, fixture->parents[wid]);
    atomicIncExplicit(&fixture->ready, memory_order_release);

    uint32_t observed_generation = 0;
    for (;;)
    {
        uint32_t generation;
        while ((generation = (uint32_t) atomicLoadExplicit(&fixture->command_generation, memory_order_acquire)) ==
               observed_generation)
        {
            YIELD_THREAD();
        }
        observed_generation = generation;
        const admission_race_command_t command =
            (admission_race_command_t) atomicLoadExplicit(&fixture->command, memory_order_relaxed);

        if (command == kAdmissionRaceCommandOpen)
        {
            const uint32_t opens_per_worker =
                (uint32_t) atomicLoadExplicit(&fixture->opens_per_worker, memory_order_relaxed);
            const uint32_t round = (uint32_t) atomicLoadExplicit(&fixture->round, memory_order_relaxed);
            for (uint32_t index = 0; index < opens_per_worker; ++index)
            {
                const mux_cid_t cid = (round * 10000U) + ((mux_cid_t) wid * 1000U) + index + 1U;
                raceSendOpen(fixture, wid, cid);
            }
        }
        else if (command == kAdmissionRaceCommandDestroyOne &&
                 (wid_t) atomicLoadExplicit(&fixture->destroy_wid, memory_order_relaxed) == wid)
        {
            muxserver_lstate_t *parent_ls = lineGetState(fixture->parents[wid], fixture->mux);
            require(parent_ls->child_next != NULL, "selected race worker had no admitted child to destroy");
            fixture->expected_child_close_cid[wid] = parent_ls->child_next->connection_id;
            muxserverTunnelDownStreamFinish(fixture->mux, parent_ls->child_next->l);
            require(fixture->expected_child_close_cid[wid] == 0,
                    "explicit child destruction did not emit its matching Close");
        }
        else if (command == kAdmissionRaceCommandCleanupAndExit)
        {
            muxserver_tstate_t *ts = tunnelGetState(fixture->mux);
            muxserverHandleParentLoss(fixture->mux, fixture->parents[wid], false);
            lineDestroy(fixture->parents[wid]);
            fixture->parents[wid] = NULL;
            require(ts->worker_states[wid].detached_registry.count == 0,
                    "aggregate race retained a detached child during teardown");
            if (ts->worker_states[wid].child_idle_table != NULL)
            {
                require(localidletableGetItemCount(ts->worker_states[wid].child_idle_table) == 0,
                        "aggregate race retained an idle item during teardown");
                localidletableDestroy(ts->worker_states[wid].child_idle_table);
                ts->worker_states[wid].child_idle_table = NULL;
            }
        }

        racePublishTimerCount(fixture, wid);
        atomicIncExplicit(&fixture->command_completed, memory_order_release);
        if (command == kAdmissionRaceCommandCleanupAndExit)
        {
            break;
        }
    }
    testWorkerUnbindWID();
    return 0;
}

static void raceFixtureSetup(admission_race_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    fixture->wios_master   = masterpoolCreateWithCapacity(32);
    fixture->parent_master = masterpoolCreateWithCapacity(32);
    require(fixture->wios_master != NULL && fixture->parent_master != NULL,
            "failed to create aggregate race shared pools");

    GSTATE.flag_initialized      = true;
    GSTATE.workers               = fixture->workers;
    GSTATE.workers_count         = kRaceWorkers;
    GSTATE.shortcut_buffer_pools = fixture->pools;
    GSTATE.shortcut_wios_pools   = fixture->wios_pools;
    GSTATE.shortcut_loops        = fixture->loops;

    for (wid_t wid = 0; wid < kRaceWorkers; ++wid)
    {
        fixture->large_masters[wid] = masterpoolCreateWithCapacity(16);
        fixture->small_masters[wid] = masterpoolCreateWithCapacity(16);
        require(fixture->large_masters[wid] != NULL && fixture->small_masters[wid] != NULL,
                "failed to create race buffer masters");
        fixture->pools[wid] = bufferpoolCreate(
            fixture->large_masters[wid], fixture->small_masters[wid], 8, kRaceBufferSize, kRaceBufferSize);
        fixture->wios_pools[wid] =
            threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(fixture->wios_master, sizeof(wio_t), 8);
        require(fixture->pools[wid] != NULL && fixture->wios_pools[wid] != NULL, "failed to create race worker pools");
        bufferpoolUpdateAllocationPaddings(fixture->pools[wid], kMuxFrameLength * 2U, kMuxFrameLength * 2U);
        testWorkerBindWID(wid);
        fixture->loops[wid] = wloopCreate(WLOOP_FLAG_AUTO_FREE, fixture->pools[wid], wid);
        require(fixture->loops[wid] != NULL, "failed to create race worker loop");
        fixture->workers[wid]      = (worker_t) {.wid            = wid,
                                                 .loop           = fixture->loops[wid],
                                                 .buffer_pool    = fixture->pools[wid],
                                                 .wios_pool      = fixture->wios_pools[wid],
                                                 .has_event_loop = true};
        fixture->parent_pools[wid] = genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(
            fixture->parent_master, sizeof(line_t) + sizeof(muxserver_lstate_t), 4);
        require(fixture->parent_pools[wid] != NULL, "failed to create race parent line pool");
    }
    testWorkerUnbindWID();

    fixture->prev = tunnelCreate(NULL, 0, 0);
    fixture->mux  = tunnelCreate(NULL,
                                sizeof(muxserver_tstate_t) + (kRaceWorkers * sizeof(muxserver_worker_state_t)),
                                sizeof(muxserver_lstate_t));
    fixture->next = tunnelCreate(NULL, 0, 0);
    require(fixture->prev != NULL && fixture->mux != NULL && fixture->next != NULL,
            "failed to create aggregate race tunnels");
    tunnelBind(fixture->prev, fixture->mux);
    tunnelBind(fixture->mux, fixture->next);
    fixture->prev->fnEstD     = racePrevEst;
    fixture->prev->fnPayloadD = racePrevPayload;
    fixture->next->fnInitU    = raceNextInit;
    fixture->next->fnFinU     = raceNextFinish;

    muxserver_tstate_t *ts            = tunnelGetState(fixture->mux);
    ts->child_buffer_limit            = kMuxDefaultChildBufferLimit;
    ts->child_buffer_pause_tolerance  = kMuxDefaultChildBufferPauseTolerance;
    ts->child_buffer_resume_threshold = kMuxDefaultChildBufferResumeThreshold;
    ts->parent_buffer_limit           = kMuxDefaultParentBufferLimit;
    ts->detached_buffer_limit         = kMuxMinimumDetachedBufferLimit;
    ts->detached_child_limit          = kMuxMinimumDetachedChildLimit;
    ts->max_children                  = 32;
    ts->initial_child_idle_timeout_ms = 60000;
    ts->active_child_idle_timeout_ms  = 60000;
    ts->memory_high_watermark_percent = 85;
    ts->memory_low_watermark_percent  = 75;
    ts->workers_count                 = kRaceWorkers;

    fixture->chain                      = tunnelchainCreate(kRaceWorkers);
    fixture->chain->sum_line_state_size = fixture->mux->lstate_size;
    tunnelchainFinalize(fixture->chain);
    fixture->mux->chain = fixture->chain;
    g_race_fixture      = fixture;

    for (wid_t wid = 0; wid < kRaceWorkers; ++wid)
    {
        fixture->tasks[wid] = (admission_race_task_t) {.fixture = fixture, .wid = wid};
        require(threadCreate(&fixture->threads[wid], admissionRaceMain, &fixture->tasks[wid]) == kWThreadErrorNone,
                "failed to create persistent registered aggregate worker");
    }
    while (atomicLoadExplicit(&fixture->ready, memory_order_acquire) != kRaceWorkers)
    {
        YIELD_THREAD();
    }
}

static uint32_t raceTotal(const atomic_uint values[kRaceWorkers])
{
    uint32_t total = 0;
    for (wid_t wid = 0; wid < kRaceWorkers; ++wid)
    {
        total += (uint32_t) atomicLoadRelaxed(&values[wid]);
    }
    return total;
}

static uint32_t raceTimerCount(const admission_race_fixture_t *fixture)
{
    uint32_t total = 0;
    for (wid_t wid = 0; wid < kRaceWorkers; ++wid)
    {
        total += (uint32_t) atomicLoadExplicit(&((admission_race_fixture_t *) (uintptr_t) fixture)->timer_counts[wid],
                                               memory_order_acquire);
    }
    return total;
}

static void runCommand(admission_race_fixture_t *fixture, admission_race_command_t command)
{
    atomicStoreExplicit(&fixture->command, (unsigned int) command, memory_order_relaxed);
    atomicStoreRelaxed(&fixture->command_completed, 0);
    atomicIncExplicit(&fixture->command_generation, memory_order_release);
    while (atomicLoadExplicit(&fixture->command_completed, memory_order_acquire) != kRaceWorkers)
    {
        YIELD_THREAD();
    }
}

static void runRace(admission_race_fixture_t *fixture, uint32_t opens_per_worker, uint32_t round)
{
    atomicStoreExplicit(&fixture->opens_per_worker, opens_per_worker, memory_order_relaxed);
    atomicStoreExplicit(&fixture->round, round, memory_order_relaxed);
    runCommand(fixture, kAdmissionRaceCommandOpen);
}

static void destroyOneChild(admission_race_fixture_t *fixture)
{
    for (wid_t wid = 0; wid < kRaceWorkers; ++wid)
    {
        if (atomicLoadRelaxed(&fixture->admitted[wid]) != 0)
        {
            atomicStoreExplicit(&fixture->destroy_wid, wid, memory_order_relaxed);
            runCommand(fixture, kAdmissionRaceCommandDestroyOne);
            return;
        }
    }
    require(false, "aggregate race had no admitted child to destroy");
}

static void raceFixtureTeardown(admission_race_fixture_t *fixture)
{
    muxserver_tstate_t *ts = tunnelGetState(fixture->mux);
    runCommand(fixture, kAdmissionRaceCommandCleanupAndExit);
    for (wid_t wid = 0; wid < kRaceWorkers; ++wid)
    {
        require(threadJoin(fixture->threads[wid]) == 0, "failed to join persistent aggregate worker");
    }
    require(atomicLoadRelaxed(&ts->live_children_count) == 0,
            "aggregate race retained a live-child reservation during teardown");

    tunnelchainDestroy(fixture->chain);
    for (wid_t wid = 0; wid < kRaceWorkers; ++wid)
    {
        genericpoolDestroy(fixture->parent_pools[wid]);
        wloopDestroy(&fixture->loops[wid]);
        threadsafegenericpoolDestroy(fixture->wios_pools[wid]);
        bufferpoolDestroy(fixture->pools[wid]);
        masterpoolMakeEmpty(fixture->large_masters[wid]);
        masterpoolMakeEmpty(fixture->small_masters[wid]);
        masterpoolDestroy(fixture->large_masters[wid]);
        masterpoolDestroy(fixture->small_masters[wid]);
    }
    masterpoolDestroy(fixture->parent_master);
    masterpoolMakeEmpty(fixture->wios_master);
    masterpoolDestroy(fixture->wios_master);
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->mux);
    tunnelDestroy(fixture->next);
    GSTATE.flag_initialized      = false;
    GSTATE.workers               = NULL;
    GSTATE.workers_count         = 0;
    GSTATE.shortcut_buffer_pools = NULL;
    GSTATE.shortcut_wios_pools   = NULL;
    GSTATE.shortcut_loops        = NULL;
    g_race_fixture               = NULL;
}

static void runAggregateCase(system_memory_provider_result_t memory_result, uint32_t hard_ceiling,
                             uint32_t fallback_ceiling, uint32_t expected_ceiling, const char *case_name)
{
    puts(case_name);
    admission_race_fixture_t fixture;
    raceFixtureSetup(&fixture);
    muxserver_tstate_t *ts                = tunnelGetState(fixture.mux);
    ts->max_live_children                 = hard_ceiling;
    ts->memory_fallback_max_live_children = fallback_ceiling;

    race_memory_provider_t provider = {.result = memory_result};
    atomicStoreU64Relaxed(&provider.now_ms, 100);
    system_load_state_t sampler = {0};
    require(
        systemLoadSamplerTryInitWithMemoryTestHooks(&sampler, raceMemoryProvider, raceMemoryNow, &provider, NULL, NULL),
        "failed to initialize aggregate race sampler");
    system_load_state_t *saved_sampler = GSTATE.system_load;
    GSTATE.system_load                 = &sampler;

    runRace(&fixture, kRaceOpensPerRound, 1);
    require((uint32_t) atomicLoadRelaxed(&ts->live_children_count) == expected_ceiling,
            "production parser race exceeded or underfilled the aggregate ceiling");
    require(raceTotal(fixture.admitted) == expected_ceiling,
            "production parser race initialized the wrong number of children");
    require(raceTotal(fixture.rejected) == (kRaceWorkers * kRaceOpensPerRound) - expected_ceiling,
            "production parser race emitted the wrong number of matching Close frames");
    require(raceTimerCount(&fixture) == expected_ceiling,
            "production parser race timer count disagreed with reservations");
    for (wid_t wid = 0; wid < kRaceWorkers; ++wid)
    {
        require(lineIsAlive(fixture.parents[wid]), "aggregate resource rejection destroyed a parent");
    }

    destroyOneChild(&fixture);
    require((uint32_t) atomicLoadRelaxed(&ts->live_children_count) == expected_ceiling - 1U,
            "one production child destruction did not release exactly one aggregate slot");
    require(raceTimerCount(&fixture) == expected_ceiling - 1U,
            "one production child destruction did not release exactly one timer");
    const uint32_t admitted_before = raceTotal(fixture.admitted);
    const uint32_t rejected_before = raceTotal(fixture.rejected);
    runRace(&fixture, 1, 2);
    require(raceTotal(fixture.admitted) == admitted_before + 1U &&
                raceTotal(fixture.rejected) == rejected_before + 1U &&
                (uint32_t) atomicLoadRelaxed(&ts->live_children_count) == expected_ceiling,
            "racing replacement Opens did not reuse exactly one released aggregate slot");

    GSTATE.system_load = saved_sampler;
    systemLoadSamplerDestroy(&sampler);
    raceFixtureTeardown(&fixture);
}

int main(void)
{
    runAggregateCase(
        kSystemMemoryProviderOk, 5, 2, 5, "MuxServer production parser races registered workers at the hard ceiling");
    runAggregateCase(kSystemMemoryProviderUnsupported,
                     6,
                     3,
                     3,
                     "MuxServer production parser races registered workers at the fallback ceiling");
    puts("muxserver_admission_concurrency_test: all cases passed");
    return 0;
}
