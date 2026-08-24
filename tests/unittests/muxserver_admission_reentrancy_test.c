#include "MuxServer/structure.h"

#include "tunnel_line_failure_harness.h"

enum
{
    kServerTestBufferSize = 64 * 1024,
    kServerTestMaxParents = 4,
};

typedef struct server_memory_provider_s
{
    atomic_ullong                   now_ms;
    uint64_t                        host_total;
    uint64_t                        host_available;
    uint64_t                        cgroup_limit;
    uint64_t                        cgroup_current;
    system_memory_provider_result_t result;
    bool                            cgroup_limited;
} server_memory_provider_t;

typedef struct muxserver_admission_fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  parent_lines;
    twf_trace_t      trace;
    tunnel_chain_t  *chain;
    tunnel_t        *prev;
    tunnel_t        *mux;
    tunnel_t        *next;
    line_t          *parents[kServerTestMaxParents];
    uint32_t         parent_count;
    uint8_t         *capture;
    uint64_t         now_ms;
    uint32_t         quiet_prev_payloads;
} muxserver_admission_fixture_t;

static muxserver_admission_fixture_t *g_server_fixture = NULL;

static uint64_t serverClockNow(void *userdata)
{
    return ((muxserver_admission_fixture_t *) userdata)->now_ms;
}

static uint64_t serverMemoryNow(void *userdata)
{
    server_memory_provider_t *provider = userdata;
    return atomicLoadU64Relaxed(&provider->now_ms);
}

static system_memory_provider_result_t serverMemoryProvider(void *userdata, system_memory_snapshot_t *snapshot)
{
    server_memory_provider_t *provider = userdata;
    if (provider->result != kSystemMemoryProviderOk)
    {
        return provider->result;
    }

    snapshot->host_total_bytes     = provider->host_total;
    snapshot->host_available_bytes = provider->host_available;
    snapshot->cgroup_limit_bytes   = provider->cgroup_limit;
    snapshot->cgroup_current_bytes = provider->cgroup_current;
    snapshot->cgroup_available_bytes =
        provider->cgroup_current >= provider->cgroup_limit ? 0 : provider->cgroup_limit - provider->cgroup_current;
    snapshot->cgroup_limited = provider->cgroup_limited;
    return kSystemMemoryProviderOk;
}

static void writeFrameHeader(uint8_t *out, uint32_t length, uint8_t flags, mux_cid_t cid)
{
    out[0] = (uint8_t) ((length >> 8U) & 0xFFU);
    out[1] = (uint8_t) (length & 0xFFU);
    out[2] = flags;
    out[3] = 0;
    out[4] = (uint8_t) ((cid >> 24U) & 0xFFU);
    out[5] = (uint8_t) ((cid >> 16U) & 0xFFU);
    out[6] = (uint8_t) ((cid >> 8U) & 0xFFU);
    out[7] = (uint8_t) (cid & 0xFFU);
}

static void forgetParent(muxserver_admission_fixture_t *fixture, line_t *parent_l)
{
    for (uint32_t i = 0; i < fixture->parent_count; ++i)
    {
        if (fixture->parents[i] == parent_l)
        {
            fixture->parents[i] = NULL;
            return;
        }
    }
    twfRequire(false, "re-entrant callback destroyed an unknown parent");
}

static line_t *fixtureCreateParent(muxserver_admission_fixture_t *fixture)
{
    twfRequire(fixture->parent_count < kServerTestMaxParents, "too many MuxServer parents in one fixture");
    line_t *parent_l                          = twfLinePoolCreateLine(&fixture->parent_lines);
    fixture->parents[fixture->parent_count++] = parent_l;
    muxserverTunnelUpStreamInit(fixture->mux, parent_l);
    return parent_l;
}

static void fixtureSetup(muxserver_admission_fixture_t *fixture, uint32_t capture_capacity)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kServerTestBufferSize, kMuxFrameLength * 2U);

    fixture->capture = memoryAllocate(max(capture_capacity, 1U));
    twfRequire(fixture->capture != NULL, "failed to allocate MuxServer admission capture storage");
    fixture->trace.capture          = fixture->capture;
    fixture->trace.capture_capacity = capture_capacity;

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->mux =
        tunnelCreate(NULL, sizeof(muxserver_tstate_t) + sizeof(muxserver_worker_state_t), sizeof(muxserver_lstate_t));
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->mux != NULL, "failed to create the MuxServer admission fixture tunnel");
    tunnelBind(fixture->prev, fixture->mux);
    tunnelBind(fixture->mux, fixture->next);

    muxserver_tstate_t *ts                = tunnelGetState(fixture->mux);
    ts->child_buffer_limit                = kMuxDefaultChildBufferLimit;
    ts->child_buffer_pause_tolerance      = kMuxDefaultChildBufferPauseTolerance;
    ts->child_buffer_resume_threshold     = kMuxDefaultChildBufferResumeThreshold;
    ts->parent_buffer_limit               = kMuxDefaultParentBufferLimit;
    ts->detached_buffer_limit             = kMuxMinimumDetachedBufferLimit;
    ts->detached_child_limit              = kMuxMinimumDetachedChildLimit;
    ts->max_children                      = 16;
    ts->max_live_children                 = 16;
    ts->memory_fallback_max_live_children = 16;
    ts->initial_child_idle_timeout_ms     = 60000;
    ts->active_child_idle_timeout_ms      = 60000;
    ts->memory_high_watermark_percent     = 85;
    ts->memory_low_watermark_percent      = 75;
    ts->workers_count                     = 1;
    ts->test_now_ms                       = serverClockNow;
    ts->test_now_userdata                 = fixture;
    fixture->now_ms                       = 100;

    fixture->chain                      = tunnelchainCreate(1);
    fixture->chain->sum_line_state_size = fixture->mux->lstate_size;
    tunnelchainFinalize(fixture->chain);
    fixture->mux->chain = fixture->chain;

    twfLinePoolSetup(&fixture->parent_lines, fixture->mux->lstate_size, kServerTestMaxParents);
    g_server_fixture = fixture;
}

static void fixtureDestroyIdleTable(muxserver_admission_fixture_t *fixture)
{
    muxserver_tstate_t *ts    = tunnelGetState(fixture->mux);
    local_idle_table_t *table = ts->worker_states[0].child_idle_table;
    if (table == NULL)
    {
        return;
    }

    twfRequireEqualU32(
        (uint32_t) localidletableGetItemCount(table), 0, "MuxServer fixture retained a child idle entry");
    localidletableDestroy(table);
    ts->worker_states[0].child_idle_table = NULL;
}

static void fixtureTeardown(muxserver_admission_fixture_t *fixture)
{
    for (uint32_t i = 0; i < fixture->parent_count; ++i)
    {
        line_t *parent_l = fixture->parents[i];
        if (parent_l == NULL)
        {
            continue;
        }

        muxserver_lstate_t *parent_ls = lineGetState(parent_l, fixture->mux);
        if (parent_ls->l != NULL)
        {
            muxserverHandleParentLoss(fixture->mux, parent_l, false);
        }
        lineDestroy(parent_l);
        fixture->parents[i] = NULL;
    }

    muxserver_tstate_t *ts = tunnelGetState(fixture->mux);
    twfRequireEqualU32((uint32_t) atomicLoadRelaxed(&ts->live_children_count),
                       0,
                       "MuxServer fixture retained an aggregate child reservation");
    fixtureDestroyIdleTable(fixture);
    twfRequireNoLeakedBuffers();

    tunnelchainDestroy(fixture->chain);
    twfLinePoolTeardown(&fixture->parent_lines);
    memoryFree(fixture->capture);
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->mux);
    tunnelDestroy(fixture->next);
    g_server_fixture = NULL;
    twfWorkerEnvTeardown(&fixture->env);
}

static void sendFrame(muxserver_admission_fixture_t *fixture, line_t *parent_l, mux_cid_t cid, uint8_t flags,
                      uint8_t body)
{
    const uint32_t length = flags == kMuxFlagData ? 1U : 0U;
    sbuf_t        *frame  = bufferpoolGetLargeBuffer(fixture->env.pool);
    sbufSetLength(frame, kMuxFrameLength + length);
    writeFrameHeader(sbufGetMutablePtr(frame), length, flags, cid);
    if (length != 0)
    {
        sbufGetMutablePtr(frame)[kMuxFrameLength] = body;
    }
    muxserverTunnelUpStreamPayload(fixture->mux, parent_l, frame);
}

static void requireCloseFrame(const muxserver_admission_fixture_t *fixture, mux_cid_t cid)
{
    twfRequireEqualU32(fixture->trace.capture_len, kMuxFrameLength, "rejection emitted the wrong byte count");
    const uint8_t  *raw = fixture->capture;
    const mux_cid_t encoded_cid =
        ((mux_cid_t) raw[4] << 24U) | ((mux_cid_t) raw[5] << 16U) | ((mux_cid_t) raw[6] << 8U) | (mux_cid_t) raw[7];
    twfRequire(raw[0] == 0 && raw[1] == 0 && raw[2] == kMuxFlagClose && encoded_cid == cid,
               "rejection emitted a malformed Close frame");
}

static void quietPrevPayload(tunnel_t *prev, line_t *line, sbuf_t *buf)
{
    discard                        prev;
    muxserver_admission_fixture_t *fixture = g_server_fixture;
    twfRequire(fixture != NULL, "quiet rejection callback ran outside its fixture");
    ++fixture->quiet_prev_payloads;
    lineReuseBuffer(line, buf);
}

static void destroyParentOnRejection(tunnel_t *prev, line_t *parent_l, sbuf_t *buf)
{
    muxserver_admission_fixture_t *fixture = g_server_fixture;
    twfRequire(fixture != NULL && prev == fixture->prev, "re-entrant rejection reached the wrong previous tunnel");
    ++fixture->trace.prev_payload;
    twfCapture(&fixture->trace, buf);
    lineReuseBuffer(parent_l, buf);

    muxserverTunnelUpStreamFinish(fixture->mux, parent_l);
    lineDestroy(parent_l);
    forgetParent(fixture, parent_l);
}

static void destroyChildDuringInit(tunnel_t *next, line_t *child_l)
{
    muxserver_admission_fixture_t *fixture = g_server_fixture;
    twfRequire(fixture != NULL && next == fixture->next, "child Init reached the wrong next tunnel");
    ++fixture->trace.next_init;
    muxserverTunnelDownStreamFinish(fixture->mux, child_l);
}

static void destroyParentDuringChildInit(tunnel_t *next, line_t *child_l)
{
    discard                        child_l;
    muxserver_admission_fixture_t *fixture = g_server_fixture;
    twfRequire(fixture != NULL && next == fixture->next, "parent-destroying Init reached the wrong next tunnel");
    ++fixture->trace.next_init;

    line_t *parent_l = fixture->parents[0];
    muxserverTunnelUpStreamFinish(fixture->mux, parent_l);
    lineDestroy(parent_l);
    forgetParent(fixture, parent_l);
}

static void caseExactPerParentCapPreservesSiblings(void)
{
    twfSetCase("MuxServer admits exactly the per-parent cap and rejects the next CID");
    muxserver_admission_fixture_t fixture;
    fixtureSetup(&fixture, kMuxFrameLength);
    line_t             *parent_l = fixtureCreateParent(&fixture);
    muxserver_tstate_t *ts       = tunnelGetState(fixture.mux);
    ts->max_children             = 3;

    sendFrame(&fixture, parent_l, 101, kMuxFlagOpen, 0);
    sendFrame(&fixture, parent_l, 205, kMuxFlagOpen, 0);
    sendFrame(&fixture, parent_l, 409, kMuxFlagOpen, 0);
    muxserver_lstate_t *parent_ls = lineGetState(parent_l, fixture.mux);
    twfRequireEqualU32(parent_ls->children_count, 3, "the exact per-parent cap was not admitted");
    twfRequireEqualU32(fixture.trace.next_init, 3, "an admitted child was not initialized exactly once");

    sendFrame(&fixture, parent_l, 811, kMuxFlagOpen, 0);
    twfRequire(lineIsAlive(parent_l), "ordinary resource rejection closed the parent");
    twfRequireEqualU32(parent_ls->children_count, 3, "resource rejection changed the sibling set");
    twfRequireEqualU32(fixture.trace.next_init, 3, "resource rejection allocated a temporary child");
    twfRequireEqualU32(
        (uint32_t) atomicLoadRelaxed(&ts->live_children_count), 3, "resource rejection changed aggregate reservations");
    requireCloseFrame(&fixture, 811);

    fixture.trace.capture_len = 0;
    sendFrame(&fixture, parent_l, 205, kMuxFlagData, 0x5A);
    twfRequireEqualU32(fixture.trace.next_payload, 1, "an admitted sibling stopped carrying Data");
    twfRequire(fixture.capture[0] == 0x5A, "the admitted sibling Data byte was corrupted");
    fixtureTeardown(&fixture);
}

static void caseAggregateCapAcrossParentsReusesOneReleasedSlot(void)
{
    twfSetCase("MuxServer aggregate cap spans parents and one destruction releases one slot");
    muxserver_admission_fixture_t fixture;
    fixtureSetup(&fixture, 2U * kMuxFrameLength);
    muxserver_tstate_t *ts                = tunnelGetState(fixture.mux);
    ts->max_live_children                 = 3;
    ts->memory_fallback_max_live_children = 3;
    line_t *first_parent                  = fixtureCreateParent(&fixture);
    line_t *second_parent                 = fixtureCreateParent(&fixture);

    sendFrame(&fixture, first_parent, 11, kMuxFlagOpen, 0);
    sendFrame(&fixture, first_parent, 13, kMuxFlagOpen, 0);
    sendFrame(&fixture, second_parent, 17, kMuxFlagOpen, 0);
    sendFrame(&fixture, second_parent, 19, kMuxFlagOpen, 0);
    muxserver_lstate_t *second_parent_ls = lineGetState(second_parent, fixture.mux);
    twfRequireEqualU32(
        (uint32_t) atomicLoadRelaxed(&ts->live_children_count), 3, "aggregate cap was overrun across parents");
    twfRequireEqualU32(
        second_parent_ls->children_count, 1, "aggregate rejection allocated a child on the second parent");

    muxserver_lstate_t *first_parent_ls = lineGetState(first_parent, fixture.mux);
    line_t             *victim_l        = first_parent_ls->child_next->l;
    lineLock(victim_l);
    muxserverTunnelDownStreamFinish(fixture.mux, victim_l);
    twfRequireOwnedLineReclaimed(victim_l, "MuxServer aggregate slot release");
    twfRequireEqualU32((uint32_t) atomicLoadRelaxed(&ts->live_children_count),
                       2,
                       "one child destruction did not release exactly one slot");

    sendFrame(&fixture, second_parent, 23, kMuxFlagOpen, 0);
    twfRequireEqualU32(
        (uint32_t) atomicLoadRelaxed(&ts->live_children_count), 3, "the released aggregate slot was not reusable");
    twfRequireEqualU32(
        second_parent_ls->children_count, 2, "the replacement child was not attached to the requesting parent");
    fixtureTeardown(&fixture);
}

static void caseMemoryAdmissionDrivesProductionParser(void)
{
    twfSetCase("MuxServer production Open parser honors pressure hysteresis and stale fallback");
    muxserver_admission_fixture_t fixture;
    fixtureSetup(&fixture, 6U * kMuxFrameLength);
    muxserver_tstate_t *ts                = tunnelGetState(fixture.mux);
    ts->max_live_children                 = 5;
    ts->memory_fallback_max_live_children = 2;
    line_t *parent_l                      = fixtureCreateParent(&fixture);

    system_load_state_t sampler = {0};
    twfRequire(systemLoadSamplerTryInit(&sampler), "failed to initialize the parser memory sampler");
    server_memory_provider_t provider = {.host_total     = 1000,
                                         .host_available = 500,
                                         .cgroup_limit   = 1000,
                                         .cgroup_current = 500,
                                         .result         = kSystemMemoryProviderOk,
                                         .cgroup_limited = true};
    atomicStoreU64Relaxed(&provider.now_ms, 100);
    systemLoadSamplerSetMemoryTestHooks(&sampler, serverMemoryProvider, serverMemoryNow, &provider);
    system_load_state_t *saved_sampler = GSTATE.system_load;
    GSTATE.system_load                 = &sampler;
    muxserver_lstate_t *parent_ls      = lineGetState(parent_l, fixture.mux);

    twfRequire(systemLoadSamplerUpdate(&sampler), "failed to publish abundant parser memory");
    sendFrame(&fixture, parent_l, 31, kMuxFlagOpen, 0);
    twfRequireEqualU32(parent_ls->children_count, 1, "fresh abundant memory did not admit an Open");

    provider.host_available = 150;
    atomicStoreU64Relaxed(&provider.now_ms, 200);
    twfRequire(systemLoadSamplerUpdate(&sampler), "failed to publish host pressure");
    sendFrame(&fixture, parent_l, 37, kMuxFlagOpen, 0);
    twfRequireEqualU32(parent_ls->children_count, 1, "fresh host pressure admitted an Open");

    provider.host_available = 200;
    atomicStoreU64Relaxed(&provider.now_ms, 300);
    twfRequire(systemLoadSamplerUpdate(&sampler), "failed to publish hysteresis-band memory");
    sendFrame(&fixture, parent_l, 41, kMuxFlagOpen, 0);
    twfRequireEqualU32(parent_ls->children_count, 1, "the hysteresis band reopened parser admission");

    provider.host_available = 300;
    provider.cgroup_current = 700;
    atomicStoreU64Relaxed(&provider.now_ms, 400);
    twfRequire(systemLoadSamplerUpdate(&sampler), "failed to publish recovered memory");
    sendFrame(&fixture, parent_l, 43, kMuxFlagOpen, 0);
    twfRequireEqualU32(parent_ls->children_count, 2, "low-watermark recovery did not reopen parser admission");

    provider.cgroup_current = 900;
    atomicStoreU64Relaxed(&provider.now_ms, 500);
    twfRequire(systemLoadSamplerUpdate(&sampler), "failed to publish finite-cgroup pressure");
    sendFrame(&fixture, parent_l, 47, kMuxFlagOpen, 0);
    twfRequireEqualU32(parent_ls->children_count, 2, "finite-cgroup pressure admitted an Open");

    atomicStoreU64Relaxed(&provider.now_ms, 1601);
    sendFrame(&fixture, parent_l, 53, kMuxFlagOpen, 0);
    twfRequireEqualU32(parent_ls->children_count, 2, "a stale snapshot reopened a pressure-closed parser gate");

    atomicStoreU64Relaxed(&ts->memory_admission_state, 0);
    sendFrame(&fixture, parent_l, 59, kMuxFlagOpen, 0);
    twfRequireEqualU32(parent_ls->children_count, 2, "stale fallback exceeded its conservative live-child ceiling");

    GSTATE.system_load = saved_sampler;
    systemLoadSamplerDestroy(&sampler);
    fixtureTeardown(&fixture);
}

static void caseReserveBoundaryAndTwoConditionRecovery(void)
{
    twfSetCase("MuxServer production parser applies reserve equality and both recovery low-water conditions");
    muxserver_admission_fixture_t fixture;
    fixtureSetup(&fixture, 4U * kMuxFrameLength);
    muxserver_tstate_t *ts                = tunnelGetState(fixture.mux);
    ts->max_live_children                 = 8;
    ts->memory_fallback_max_live_children = 2;
    ts->memory_reserve                    = 100;
    line_t *parent_l                      = fixtureCreateParent(&fixture);

    server_memory_provider_t provider = {.host_total     = 1000,
                                         .host_available = 500,
                                         .cgroup_limit   = 200,
                                         .cgroup_current = 50,
                                         .result         = kSystemMemoryProviderOk,
                                         .cgroup_limited = true};
    atomicStoreU64Relaxed(&provider.now_ms, 100);
    system_load_state_t sampler = {0};
    twfRequire(systemLoadSamplerTryInitWithMemoryTestHooks(
                   &sampler, serverMemoryProvider, serverMemoryNow, &provider, NULL, NULL),
               "failed to initialize isolated reserve sampler");
    system_load_state_t *saved_sampler = GSTATE.system_load;
    GSTATE.system_load                 = &sampler;
    muxserver_lstate_t *parent_ls      = lineGetState(parent_l, fixture.mux);
    sendFrame(&fixture, parent_l, 301, kMuxFlagOpen, 0);
    twfRequireEqualU32(parent_ls->children_count, 1, "abundant reserve baseline did not admit a sibling");

    provider.cgroup_current = 100;
    atomicStoreU64Relaxed(&provider.now_ms, 200);
    twfRequire(systemLoadSamplerUpdate(&sampler), "failed to publish reserve-equality snapshot");
    fixture.trace.capture_len  = 0;
    const uint32_t init_before = fixture.trace.next_init;
    sendFrame(&fixture, parent_l, 302, kMuxFlagOpen, 0);
    requireCloseFrame(&fixture, 302);
    twfRequireEqualU32(parent_ls->children_count, 1, "reserve equality allocated a child");
    twfRequireEqualU32(fixture.trace.next_init, init_before, "reserve equality initialized a rejected child");
    twfRequire(lineIsAlive(parent_l), "reserve equality destroyed the parent or sibling");

    provider.cgroup_current = 101;
    atomicStoreU64Relaxed(&provider.now_ms, 300);
    twfRequire(systemLoadSamplerUpdate(&sampler), "failed to publish below-reserve snapshot");
    fixture.trace.capture_len = 0;
    sendFrame(&fixture, parent_l, 303, kMuxFlagOpen, 0);
    requireCloseFrame(&fixture, 303);
    twfRequireEqualU32(parent_ls->children_count, 1, "below-reserve pressure allocated a child");

    provider.cgroup_limit   = 1000;
    provider.cgroup_current = 800;
    atomicStoreU64Relaxed(&provider.now_ms, 400);
    twfRequire(systemLoadSamplerUpdate(&sampler), "failed to publish percentage-only recovery blocker");
    fixture.trace.capture_len = 0;
    sendFrame(&fixture, parent_l, 304, kMuxFlagOpen, 0);
    requireCloseFrame(&fixture, 304);
    twfRequireEqualU32(
        parent_ls->children_count, 1, "headroom alone reopened the gate above the percentage low watermark");

    provider.cgroup_current = 700;
    atomicStoreU64Relaxed(&provider.now_ms, 500);
    twfRequire(systemLoadSamplerUpdate(&sampler), "failed to publish complete recovery snapshot");
    sendFrame(&fixture, parent_l, 305, kMuxFlagOpen, 0);
    twfRequireEqualU32(
        parent_ls->children_count, 2, "both percentage and reserve recovery conditions did not reopen admission");

    GSTATE.system_load = saved_sampler;
    systemLoadSamplerDestroy(&sampler);
    fixtureTeardown(&fixture);
}

static void caseInitialProviderStatusUsesImmediateFallback(system_memory_provider_result_t result,
                                                           uint32_t fallback_ceiling, const char *case_name)
{
    twfSetCase(case_name);
    muxserver_admission_fixture_t fixture;
    fixtureSetup(&fixture, kMuxFrameLength);
    muxserver_tstate_t *ts                = tunnelGetState(fixture.mux);
    ts->max_live_children                 = 8;
    ts->memory_fallback_max_live_children = fallback_ceiling;
    line_t *parent_l                      = fixtureCreateParent(&fixture);

    server_memory_provider_t provider = {.result = result};
    atomicStoreU64Relaxed(&provider.now_ms, 100);
    system_load_state_t sampler = {0};
    twfRequire(systemLoadSamplerTryInitWithMemoryTestHooks(
                   &sampler, serverMemoryProvider, serverMemoryNow, &provider, NULL, NULL),
               "failed to initialize isolated initial-status sampler");
    system_load_state_t *saved_sampler = GSTATE.system_load;
    GSTATE.system_load                 = &sampler;
    muxserver_lstate_t *parent_ls      = lineGetState(parent_l, fixture.mux);

    for (uint32_t index = 0; index < fallback_ceiling; ++index)
    {
        sendFrame(&fixture, parent_l, 400U + index, kMuxFlagOpen, 0);
    }
    twfRequireEqualU32(parent_ls->children_count,
                       fallback_ceiling,
                       "initial provider status did not admit exactly the fallback ceiling");
    const uint32_t init_before = fixture.trace.next_init;
    fixture.trace.capture_len  = 0;
    sendFrame(&fixture, parent_l, 499, kMuxFlagOpen, 0);
    requireCloseFrame(&fixture, 499);
    twfRequireEqualU32(
        parent_ls->children_count, fallback_ceiling, "initial provider fallback exceeded its configured ceiling");
    twfRequireEqualU32(fixture.trace.next_init, init_before, "initial provider fallback allocated a rejected child");
    twfRequire(lineIsAlive(parent_l), "initial provider fallback rejection destroyed the parent");

    GSTATE.system_load = saved_sampler;
    systemLoadSamplerDestroy(&sampler);
    fixtureTeardown(&fixture);
}

static void caseLastValidFreshnessThenFallback(void)
{
    twfSetCase("MuxServer retains last-valid memory through one second then switches to fallback");
    muxserver_admission_fixture_t fixture;
    fixtureSetup(&fixture, kMuxFrameLength);
    muxserver_tstate_t *ts                = tunnelGetState(fixture.mux);
    ts->max_live_children                 = 5;
    ts->memory_fallback_max_live_children = 2;
    line_t                  *parent_l     = fixtureCreateParent(&fixture);
    server_memory_provider_t provider = {.host_total = 1000, .host_available = 500, .result = kSystemMemoryProviderOk};
    atomicStoreU64Relaxed(&provider.now_ms, 100);
    system_load_state_t sampler = {0};
    twfRequire(systemLoadSamplerTryInitWithMemoryTestHooks(
                   &sampler, serverMemoryProvider, serverMemoryNow, &provider, NULL, NULL),
               "failed to initialize last-valid sampler");
    system_load_state_t *saved_sampler = GSTATE.system_load;
    GSTATE.system_load                 = &sampler;
    muxserver_lstate_t *parent_ls      = lineGetState(parent_l, fixture.mux);
    sendFrame(&fixture, parent_l, 501, kMuxFlagOpen, 0);

    provider.result = kSystemMemoryProviderUnavailable;
    atomicStoreU64Relaxed(&provider.now_ms, 200);
    discard systemLoadSamplerUpdate(&sampler);
    atomicStoreU64Relaxed(&provider.now_ms, 1100);
    sendFrame(&fixture, parent_l, 502, kMuxFlagOpen, 0);
    twfRequireEqualU32(
        parent_ls->children_count, 2, "last-valid snapshot was not honored at the inclusive freshness deadline");

    atomicStoreU64Relaxed(&provider.now_ms, 1101);
    fixture.trace.capture_len = 0;
    sendFrame(&fixture, parent_l, 503, kMuxFlagOpen, 0);
    requireCloseFrame(&fixture, 503);
    twfRequireEqualU32(parent_ls->children_count, 2, "stale data did not switch to the fallback ceiling");

    GSTATE.system_load = saved_sampler;
    systemLoadSamplerDestroy(&sampler);
    fixtureTeardown(&fixture);
}

static void caseFreshAbundantUsesButNeverBypassesHardCeiling(void)
{
    twfSetCase("MuxServer fresh abundant memory returns to but never bypasses the aggregate hard ceiling");
    muxserver_admission_fixture_t fixture;
    fixtureSetup(&fixture, kMuxFrameLength);
    muxserver_tstate_t *ts                = tunnelGetState(fixture.mux);
    ts->max_live_children                 = 3;
    ts->memory_fallback_max_live_children = 1;
    line_t                  *parent_l     = fixtureCreateParent(&fixture);
    server_memory_provider_t provider = {.host_total = 1000, .host_available = 900, .result = kSystemMemoryProviderOk};
    atomicStoreU64Relaxed(&provider.now_ms, 100);
    system_load_state_t sampler = {0};
    twfRequire(systemLoadSamplerTryInitWithMemoryTestHooks(
                   &sampler, serverMemoryProvider, serverMemoryNow, &provider, NULL, NULL),
               "failed to initialize abundant sampler");
    system_load_state_t *saved_sampler = GSTATE.system_load;
    GSTATE.system_load                 = &sampler;
    muxserver_lstate_t *parent_ls      = lineGetState(parent_l, fixture.mux);
    sendFrame(&fixture, parent_l, 601, kMuxFlagOpen, 0);
    sendFrame(&fixture, parent_l, 602, kMuxFlagOpen, 0);
    sendFrame(&fixture, parent_l, 603, kMuxFlagOpen, 0);
    twfRequireEqualU32(parent_ls->children_count, 3, "abundant memory remained at the fallback ceiling");
    fixture.trace.capture_len  = 0;
    const uint32_t init_before = fixture.trace.next_init;
    sendFrame(&fixture, parent_l, 604, kMuxFlagOpen, 0);
    requireCloseFrame(&fixture, 604);
    twfRequireEqualU32(parent_ls->children_count, 3, "abundant memory bypassed the hard ceiling");
    twfRequireEqualU32(fixture.trace.next_init, init_before, "hard-ceiling rejection allocated a child");

    GSTATE.system_load = saved_sampler;
    systemLoadSamplerDestroy(&sampler);
    fixtureTeardown(&fixture);
}

static void caseRejectionCanDestroyParentReentrantly(void)
{
    twfSetCase("MuxServer rejection callback may destroy the borrowed parent re-entrantly");
    muxserver_admission_fixture_t fixture;
    fixtureSetup(&fixture, kMuxFrameLength);
    line_t             *parent_l = fixtureCreateParent(&fixture);
    muxserver_tstate_t *ts       = tunnelGetState(fixture.mux);
    ts->max_children             = 1;
    sendFrame(&fixture, parent_l, 61, kMuxFlagOpen, 0);

    fixture.prev->fnPayloadD = destroyParentOnRejection;
    sendFrame(&fixture, parent_l, 67, kMuxFlagOpen, 0);
    twfRequire(fixture.parents[0] == NULL, "the synthetic parent owner did not reclaim its line");
    twfRequireEqualU32((uint32_t) atomicLoadRelaxed(&ts->live_children_count),
                       0,
                       "re-entrant parent destruction retained the child reservation");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "re-entrant parent destruction did not finish its child");
    requireCloseFrame(&fixture, 67);
    fixtureTeardown(&fixture);
}

static void caseChildInitCanDestroyOnlyChild(void)
{
    twfSetCase("MuxServer child Init may destroy only the new owned child");
    muxserver_admission_fixture_t fixture;
    fixtureSetup(&fixture, kMuxFrameLength);
    line_t             *parent_l = fixtureCreateParent(&fixture);
    muxserver_tstate_t *ts       = tunnelGetState(fixture.mux);
    fixture.next->fnInitU        = destroyChildDuringInit;

    sendFrame(&fixture, parent_l, 71, kMuxFlagOpen, 0);
    muxserver_lstate_t *parent_ls = lineGetState(parent_l, fixture.mux);
    twfRequire(lineIsAlive(parent_l), "child-only Init rejection destroyed the parent");
    twfRequireEqualU32(parent_ls->children_count, 0, "child-only Init rejection retained its CID entry");
    twfRequireEqualU32((uint32_t) muxserver_child_map_t_size(&parent_ls->parent_state->child_map),
                       0,
                       "child-only Init rejection retained its CID index entry");
    twfRequireEqualU32((uint32_t) atomicLoadRelaxed(&ts->live_children_count),
                       0,
                       "child-only Init rejection retained its reservation");
    requireCloseFrame(&fixture, 71);
    fixtureTeardown(&fixture);
}

static void caseChildInitCanDestroyParent(void)
{
    twfSetCase("MuxServer child Init may destroy the parent and new child");
    muxserver_admission_fixture_t fixture;
    fixtureSetup(&fixture, 0);
    discard             fixtureCreateParent(&fixture);
    muxserver_tstate_t *ts = tunnelGetState(fixture.mux);
    fixture.next->fnInitU  = destroyParentDuringChildInit;

    sendFrame(&fixture, fixture.parents[0], 73, kMuxFlagOpen, 0);
    twfRequire(fixture.parents[0] == NULL, "child Init did not let the parent owner reclaim its line");
    twfRequireEqualU32(fixture.trace.next_init, 1, "the re-entrant child Init ran more than once");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "parent loss did not finish the new owned child");
    twfRequireEqualU32((uint32_t) atomicLoadRelaxed(&ts->live_children_count),
                       0,
                       "parent-destroying child Init retained its reservation");
    fixtureTeardown(&fixture);
}

static void caseDuplicatePeerDrainingCidClosesParent(void)
{
    twfSetCase("MuxServer duplicate Open cannot replace a peer-draining CID");
    muxserver_admission_fixture_t fixture;
    fixtureSetup(&fixture, 0);
    line_t             *parent_l = fixtureCreateParent(&fixture);
    muxserver_tstate_t *ts       = tunnelGetState(fixture.mux);
    sendFrame(&fixture, parent_l, 79, kMuxFlagOpen, 0);

    muxserver_lstate_t *parent_ls = lineGetState(parent_l, fixture.mux);
    muxserver_lstate_t *child_ls  = muxserverFindChildByConnectionId(parent_ls, 79);
    line_t             *child_l   = child_ls->l;
    child_ls->paused              = true;
    sendFrame(&fixture, parent_l, 79, kMuxFlagClose, 0);
    twfRequire(child_ls->close_state == kMuxServerChildClosePeerDraining,
               "the paused peer Close did not enter the draining state");
    twfRequire(muxserverFindChildByConnectionId(parent_ls, 79) == child_ls,
               "the peer-draining CID left the index prematurely");

    sendFrame(&fixture, parent_l, 79, kMuxFlagOpen, 0);
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "duplicate peer-draining Open did not close the parent");
    twfRequireLineStateZeroed(parent_l, fixture.mux, "duplicate Open retained parent state");
    twfRequireEqualU32((uint32_t) atomicLoadRelaxed(&ts->live_children_count),
                       1,
                       "detached draining child released its slot before true destruction");

    child_ls         = lineGetState(child_l, fixture.mux);
    child_ls->paused = false;
    lineLock(child_l);
    muxserverTunnelDownStreamResume(fixture.mux, child_l);
    twfRequire(! lineIsAlive(child_l), "detached Resume did not finalize the owned child");
    twfRequireOwnedLineReclaimed(child_l, "MuxServer duplicate peer-draining cleanup");
    twfRequireEqualU32((uint32_t) atomicLoadRelaxed(&ts->live_children_count),
                       0,
                       "detached final destruction did not release its reservation");
    fixtureTeardown(&fixture);
}

static void runRejectedOpenBurst(uint32_t allowed, uint64_t initial_refill_ms, uint64_t now_ms, const char *case_name)
{
    twfSetCase(case_name);
    muxserver_admission_fixture_t fixture;
    fixtureSetup(&fixture, 0);
    line_t             *parent_l = fixtureCreateParent(&fixture);
    muxserver_tstate_t *ts       = tunnelGetState(fixture.mux);
    ts->max_children             = 1;
    fixture.prev->fnPayloadD     = quietPrevPayload;
    fixture.now_ms               = now_ms;
    sendFrame(&fixture, parent_l, 83, kMuxFlagOpen, 0);

    muxserver_lstate_t *parent_ls = lineGetState(parent_l, fixture.mux);
    if (initial_refill_ms != 0)
    {
        parent_ls->parent_state->rejection_bucket.tokens         = 0;
        parent_ls->parent_state->rejection_bucket.last_refill_ms = initial_refill_ms;
    }
    for (uint32_t i = 0; i < allowed; ++i)
    {
        sendFrame(&fixture, parent_l, 1000U + i, kMuxFlagOpen, 0);
    }
    twfRequireEqualU32(fixture.quiet_prev_payloads, allowed, "rejection token bucket depleted too early");
    twfRequire(lineIsAlive(parent_l), "bounded rejection traffic closed the parent");

    sendFrame(&fixture, parent_l, 2000, kMuxFlagOpen, 0);
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "sustained rejected Opens did not close the parent");
    twfRequireLineStateZeroed(parent_l, fixture.mux, "token-bucket parent close retained MUX state");
    fixtureTeardown(&fixture);
}

int main(void)
{
    caseExactPerParentCapPreservesSiblings();
    caseAggregateCapAcrossParentsReusesOneReleasedSlot();
    caseMemoryAdmissionDrivesProductionParser();
    caseReserveBoundaryAndTwoConditionRecovery();
    caseInitialProviderStatusUsesImmediateFallback(
        kSystemMemoryProviderUnavailable, 2, "MuxServer initially unavailable sampler uses immediate fallback");
    caseInitialProviderStatusUsesImmediateFallback(
        kSystemMemoryProviderUnsupported, 1, "MuxServer initially unsupported sampler uses immediate fallback");
    caseLastValidFreshnessThenFallback();
    caseFreshAbundantUsesButNeverBypassesHardCeiling();
    caseRejectionCanDestroyParentReentrantly();
    caseChildInitCanDestroyOnlyChild();
    caseChildInitCanDestroyParent();
    caseDuplicatePeerDrainingCidClosesParent();
    runRejectedOpenBurst(
        kMuxServerRejectedOpenBurst, 0, 100, "MuxServer production parser enforces the 1024 rejected-Open burst");
    runRejectedOpenBurst(kMuxServerRejectedOpenRefillPerSecond,
                         100,
                         1100,
                         "MuxServer production parser refills 64 rejected Opens per second");

    printf("muxserver_admission_reentrancy_test: all cases passed\n");
    return 0;
}
