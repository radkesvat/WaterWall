#include "MuxServer/structure.h"

#include "tunnel_line_failure_harness.h"

enum
{
    kIdleBufferSize = 64 * 1024,
    kInitialTimeout = 10,
    kActiveTimeout  = 100,
};

typedef struct muxserver_idle_fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  parent_lines;
    twf_trace_t      trace;
    tunnel_chain_t  *chain;
    tunnel_t        *prev;
    tunnel_t        *mux;
    tunnel_t        *next;
    line_t          *parent_l;
    uint8_t          capture[8U * kMuxFrameLength];
    mux_cid_t        reentrant_cid;
    line_t          *reentrant_child;
    uintptr_t        expired_address;
    bool             reenter_on_close;
} muxserver_idle_fixture_t;

static muxserver_idle_fixture_t *g_idle_fixture;

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

static mux_cid_t readFrameCid(const uint8_t *bytes)
{
    return ((mux_cid_t) bytes[4] << 24U) | ((mux_cid_t) bytes[5] << 16U) | ((mux_cid_t) bytes[6] << 8U) |
           (mux_cid_t) bytes[7];
}

static void sendFrame(muxserver_idle_fixture_t *fixture, mux_cid_t cid, uint8_t flags, uint32_t length, uint8_t body)
{
    sbuf_t *frame = bufferpoolGetLargeBuffer(fixture->env.pool);
    sbufSetLength(frame, kMuxFrameLength + length);
    writeFrameHeader(sbufGetMutablePtr(frame), length, flags, cid);
    if (length != 0)
    {
        memorySet(sbufGetMutablePtr(frame) + kMuxFrameLength, body, length);
    }
    muxserverTunnelUpStreamPayload(fixture->mux, fixture->parent_l, frame);
}

static void idleFixtureSetup(muxserver_idle_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kIdleBufferSize, kMuxFrameLength * 2U);
    fixture->trace.capture          = fixture->capture;
    fixture->trace.capture_capacity = sizeof(fixture->capture);
    fixture->prev                   = twfCreatePrevTunnel(&fixture->trace);
    fixture->mux =
        tunnelCreate(NULL, sizeof(muxserver_tstate_t) + sizeof(muxserver_worker_state_t), sizeof(muxserver_lstate_t));
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->mux != NULL, "failed to create MuxServer idle fixture");
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
    ts->initial_child_idle_timeout_ms     = kInitialTimeout;
    ts->active_child_idle_timeout_ms      = kActiveTimeout;
    ts->memory_high_watermark_percent     = 85;
    ts->memory_low_watermark_percent      = 75;
    ts->workers_count                     = 1;

    fixture->chain                      = tunnelchainCreate(1);
    fixture->chain->sum_line_state_size = fixture->mux->lstate_size;
    tunnelchainFinalize(fixture->chain);
    fixture->mux->chain = fixture->chain;

    twfLinePoolSetup(&fixture->parent_lines, fixture->mux->lstate_size, 2);
    fixture->parent_l = twfLinePoolCreateLine(&fixture->parent_lines);
    muxserverTunnelUpStreamInit(fixture->mux, fixture->parent_l);
    g_idle_fixture = fixture;
}

static void idleFixtureDestroyTable(muxserver_idle_fixture_t *fixture)
{
    muxserver_tstate_t *ts    = tunnelGetState(fixture->mux);
    local_idle_table_t *table = ts->worker_states[0].child_idle_table;
    if (table != NULL)
    {
        twfRequireEqualU32((uint32_t) localidletableGetItemCount(table), 0, "idle fixture retained a timer item");
        localidletableDestroy(table);
        ts->worker_states[0].child_idle_table = NULL;
    }
}

static void idleFixtureTeardown(muxserver_idle_fixture_t *fixture)
{
    if (fixture->parent_l != NULL)
    {
        muxserver_lstate_t *parent_ls = lineGetState(fixture->parent_l, fixture->mux);
        if (parent_ls->l != NULL)
        {
            muxserverHandleParentLoss(fixture->mux, fixture->parent_l, false);
        }
        lineDestroy(fixture->parent_l);
        fixture->parent_l = NULL;
    }

    muxserver_tstate_t *ts = tunnelGetState(fixture->mux);
    twfRequireEqualU32(
        (uint32_t) atomicLoadRelaxed(&ts->live_children_count), 0, "idle fixture retained a live-child reservation");
    twfRequireEqualU32(ts->worker_states[0].detached_registry.count, 0, "idle fixture retained a detached child");
    idleFixtureDestroyTable(fixture);
    twfRequireNoLeakedBuffers();
    tunnelchainDestroy(fixture->chain);
    twfLinePoolTeardown(&fixture->parent_lines);
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->mux);
    tunnelDestroy(fixture->next);
    g_idle_fixture = NULL;
    twfWorkerEnvTeardown(&fixture->env);
}

static muxserver_lstate_t *findChild(muxserver_idle_fixture_t *fixture, mux_cid_t cid)
{
    muxserver_lstate_t *parent_ls = lineGetState(fixture->parent_l, fixture->mux);
    return muxserverFindChildByConnectionId(parent_ls, cid);
}

static void reenterOpenOnClose(tunnel_t *prev, line_t *parent_l, sbuf_t *buf)
{
    muxserver_idle_fixture_t *fixture = g_idle_fixture;
    twfRequire(fixture != NULL && fixture->prev == prev && fixture->parent_l == parent_l,
               "idle Close re-entry reached the wrong parent");
    twfRequireEqualU32(sbufGetLength(buf), kMuxFrameLength, "idle expiry emitted a non-control frame");
    const uint8_t *bytes = sbufGetRawPtr(buf);
    twfRequire(bytes[0] == 0 && bytes[1] == 0 && bytes[2] == kMuxFlagClose,
               "idle expiry emitted malformed Close bytes");
    twfRequire(readFrameCid(bytes) != fixture->reentrant_cid, "idle expiry closed the replacement CID");
    fixture->trace.prev_payload++;
    twfCapture(&fixture->trace, buf);
    lineReuseBuffer(parent_l, buf);

    twfRequire(fixture->reenter_on_close, "unexpected idle Close callback re-entry");
    fixture->reenter_on_close = false;
    sendFrame(fixture, fixture->reentrant_cid, kMuxFlagOpen, 0, 0);
    muxserver_lstate_t *replacement = findChild(fixture, fixture->reentrant_cid);
    twfRequire(replacement != NULL, "re-entrant replacement Open was not admitted");
    fixture->reentrant_child = replacement->l;
}

static void caseNaturalExpiryDetachesBeforeAddressReuse(void)
{
    twfSetCase("MuxServer natural expiry detaches its pointer key before re-entrant pooled address reuse");
    muxserver_idle_fixture_t fixture;
    idleFixtureSetup(&fixture);
    sendFrame(&fixture, 101, kMuxFlagOpen, 0, 0);
    muxserver_lstate_t *child_ls = findChild(&fixture, 101);
    twfRequire(child_ls != NULL, "production Open did not create child A");
    fixture.expired_address      = (uintptr_t) child_ls->l;
    muxserver_tstate_t *ts       = tunnelGetState(fixture.mux);
    local_idle_table_t *table    = ts->worker_states[0].child_idle_table;
    const uint64_t      deadline = localidletableTestGetDeadline(child_ls->child_idle_item);

    fixture.reentrant_cid    = 202;
    fixture.reenter_on_close = true;
    fixture.prev->fnPayloadD = reenterOpenOnClose;
    localidletableTestSetNowMS(table, deadline);
    localidletableTestRunExpiry(table);

    muxserver_lstate_t *parent_ls = lineGetState(fixture.parent_l, fixture.mux);
    muxserver_lstate_t *new_ls    = findChild(&fixture, 202);
    twfRequire(new_ls != NULL && fixture.reentrant_child == new_ls->l,
               "re-entrant child B was not published in the CID index");
    twfRequire((uintptr_t) new_ls->l == fixture.expired_address,
               "fixture did not deterministically exercise immediate line-address reuse");
    twfRequire(findChild(&fixture, 101) == NULL, "expired child A remained in the CID map");
    twfRequireEqualU32(parent_ls->children_count, 1, "natural expiry did not leave exactly child B attached");
    twfRequireEqualU32((uint32_t) muxserver_child_map_t_size(&parent_ls->parent_state->child_map),
                       1,
                       "natural expiry left stale CID index state");
    twfRequireEqualU32(
        (uint32_t) localidletableGetItemCount(table), 1, "natural expiry did not leave exactly B's idle item");
    twfRequireEqualU32((uint32_t) atomicLoadRelaxed(&ts->live_children_count),
                       1,
                       "natural expiry did not release A and reserve B exactly once");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "natural expiry did not finish only child A toward next");
    twfRequireEqualU32(fixture.trace.prev_payload, 1, "natural expiry emitted more than one Close(A)");
    twfRequire(lineIsAlive(fixture.parent_l), "natural child expiry destroyed the parent");
    idleFixtureTeardown(&fixture);
}

static void caseDrainCallbackSkipsSecondRemoval(void)
{
    twfSetCase("MuxServer idle drain callback accepts an item already detached from both indexes");
    muxserver_idle_fixture_t fixture;
    idleFixtureSetup(&fixture);
    sendFrame(&fixture, 303, kMuxFlagOpen, 0, 0);
    muxserver_tstate_t *ts    = tunnelGetState(fixture.mux);
    local_idle_table_t *table = ts->worker_states[0].child_idle_table;
    localidletableDrainItems(table);
    muxserver_lstate_t *parent_ls = lineGetState(fixture.parent_l, fixture.mux);
    twfRequireEqualU32(parent_ls->children_count, 0, "idle drain retained its child");
    twfRequireEqualU32((uint32_t) localidletableGetItemCount(table), 0, "idle drain retained its item");
    twfRequireEqualU32(
        (uint32_t) atomicLoadRelaxed(&ts->live_children_count), 0, "idle drain retained its reservation");
    idleFixtureTeardown(&fixture);
}

static void caseIdleActivityAndSiblingIsolation(void)
{
    twfSetCase("MuxServer idle phases refresh only on nonempty Data and preserve siblings");
    muxserver_idle_fixture_t fixture;
    idleFixtureSetup(&fixture);
    sendFrame(&fixture, 401, kMuxFlagOpen, 0, 0);
    sendFrame(&fixture, 402, kMuxFlagOpen, 0, 0);
    muxserver_lstate_t *child_ls   = findChild(&fixture, 401);
    muxserver_lstate_t *sibling_ls = findChild(&fixture, 402);
    twfRequire(child_ls != NULL && sibling_ls != NULL, "idle activity fixture did not admit both children");
    muxserver_tstate_t *ts               = tunnelGetState(fixture.mux);
    local_idle_table_t *table            = ts->worker_states[0].child_idle_table;
    const uint64_t      initial_deadline = localidletableTestGetDeadline(child_ls->child_idle_item);
    localidletableTestSetNowMS(table, initial_deadline - 1U);
    localidletableKeepIdleItemForAtleast(table, sibling_ls->child_idle_item, 1000U);

    muxserverTunnelDownStreamEst(fixture.mux, child_ls->l);
    sendFrame(&fixture, 401, kMuxFlagFlowPause, 0, 0);
    sendFrame(&fixture, 401, kMuxFlagFlowResume, 0, 0);
    sendFrame(&fixture, 401, kMuxFlagData, 0, 0);
    sbuf_t *empty = bufferpoolGetLargeBuffer(fixture.env.pool);
    muxserverTunnelDownStreamPayload(fixture.mux, child_ls->l, empty);
    twfRequire(! child_ls->child_has_payload_activity &&
                   localidletableTestGetDeadline(child_ls->child_idle_item) == initial_deadline,
               "Init/Est/flow control or zero-length Data promoted the idle phase");

    sendFrame(&fixture, 401, kMuxFlagData, 1, 0x41);
    twfRequire(child_ls->child_has_payload_activity, "nonempty incoming Data did not promote active idle");
    const uint64_t first_active_deadline = localidletableTestGetDeadline(child_ls->child_idle_item);
    twfRequire(first_active_deadline > initial_deadline, "incoming Data did not extend the idle deadline");

    localidletableTestSetNowMS(table, first_active_deadline - 1U);
    sbuf_t *outgoing = bufferpoolGetLargeBuffer(fixture.env.pool);
    sbufSetLength(outgoing, 1);
    sbufGetMutablePtr(outgoing)[0] = 0x42;
    muxserverTunnelDownStreamPayload(fixture.mux, child_ls->l, outgoing);
    const uint64_t refreshed_deadline = localidletableTestGetDeadline(child_ls->child_idle_item);
    twfRequire(refreshed_deadline > first_active_deadline, "repeated nonempty activity did not extend the deadline");

    localidletableTestSetNowMS(table, first_active_deadline);
    localidletableTestRunExpiry(table);
    twfRequire(findChild(&fixture, 401) == child_ls, "expiry at an old deadline removed a refreshed child");

    const uint32_t finishes_before = fixture.trace.next_finish;
    localidletableTestSetNowMS(table, refreshed_deadline);
    localidletableTestRunExpiry(table);
    twfRequire(findChild(&fixture, 401) == NULL, "expiry at the refreshed deadline retained the idle child");
    twfRequire(findChild(&fixture, 402) == sibling_ls && lineIsAlive(fixture.parent_l),
               "one child expiry destroyed its parent or sibling");
    twfRequireEqualU32(
        fixture.trace.next_finish, finishes_before + 1U, "one child expiry invoked Finish in an extra direction");
    const uint32_t sibling_payloads = fixture.trace.next_payload;
    sendFrame(&fixture, 402, kMuxFlagData, 1, 0x55);
    twfRequireEqualU32(
        fixture.trace.next_payload, sibling_payloads + 1U, "surviving sibling stopped dispatching production Data");
    idleFixtureTeardown(&fixture);
}

static void caseOutgoingDataIndependentlyPromotes(void)
{
    twfSetCase("MuxServer first nonempty outgoing Data independently promotes active idle");
    muxserver_idle_fixture_t fixture;
    idleFixtureSetup(&fixture);
    sendFrame(&fixture, 501, kMuxFlagOpen, 0, 0);
    muxserver_lstate_t *child_ls         = findChild(&fixture, 501);
    const uint64_t      initial_deadline = localidletableTestGetDeadline(child_ls->child_idle_item);
    muxserver_tstate_t *ts               = tunnelGetState(fixture.mux);
    local_idle_table_t *table            = ts->worker_states[0].child_idle_table;
    localidletableTestSetNowMS(table, initial_deadline - 1U);
    sbuf_t *payload = bufferpoolGetLargeBuffer(fixture.env.pool);
    sbufSetLength(payload, 1);
    sbufGetMutablePtr(payload)[0] = 0x71;
    muxserverTunnelDownStreamPayload(fixture.mux, child_ls->l, payload);
    twfRequire(child_ls->child_has_payload_activity &&
                   localidletableTestGetDeadline(child_ls->child_idle_item) > initial_deadline,
               "first nonempty outgoing Data did not promote active idle");
    idleFixtureTeardown(&fixture);
}

static void caseDetachedActualIdleExpirySendsNoParentClose(void)
{
    twfSetCase("MuxServer detached actual idle expiry releases its slot without a parent Close");
    muxserver_idle_fixture_t fixture;
    idleFixtureSetup(&fixture);
    sendFrame(&fixture, 601, kMuxFlagOpen, 0, 0);
    muxserver_lstate_t *child_ls = findChild(&fixture, 601);
    child_ls->paused             = true;
    sendFrame(&fixture, 601, kMuxFlagData, 1, 0x61);
    muxserver_tstate_t *ts       = tunnelGetState(fixture.mux);
    local_idle_table_t *table    = ts->worker_states[0].child_idle_table;
    const uint64_t      deadline = localidletableTestGetDeadline(child_ls->child_idle_item);

    muxserverHandleParentLoss(fixture.mux, fixture.parent_l, false);
    lineDestroy(fixture.parent_l);
    fixture.parent_l = NULL;
    twfRequireEqualU32(
        ts->worker_states[0].detached_registry.count, 1, "parent loss did not retain the live detached child");
    const uint32_t parent_payloads = fixture.trace.prev_payload;

    localidletableTestSetNowMS(table, deadline);
    localidletableTestRunExpiry(table);
    twfRequireEqualU32(
        ts->worker_states[0].detached_registry.count, 0, "detached idle expiry retained the child inventory");
    twfRequireEqualU32((uint32_t) atomicLoadRelaxed(&ts->live_children_count),
                       0,
                       "detached idle expiry retained the aggregate reservation");
    twfRequireEqualU32(
        fixture.trace.prev_payload, parent_payloads, "detached idle expiry emitted Close toward a missing parent");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "detached idle expiry did not finish its still-live next side");
    idleFixtureTeardown(&fixture);
}

int main(void)
{
    caseNaturalExpiryDetachesBeforeAddressReuse();
    caseDrainCallbackSkipsSecondRemoval();
    caseIdleActivityAndSiblingIsolation();
    caseOutgoingDataIndependentlyPromotes();
    caseDetachedActualIdleExpirySendsNoParentClose();
    puts("muxserver_idle_lifecycle_test: all cases passed");
    return 0;
}
