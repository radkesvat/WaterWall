#include "MuxClient/structure.h"

#include "tunnel_line_failure_harness.h"

enum
{
    kClientTestBufferSize   = 64 * 1024,
    kClientInitialChildren  = 16,
    kClientDispatchChildren = 2048,
};

typedef struct muxclient_capacity_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_chain_t  *chain;
    tunnel_t        *prev;
    tunnel_t        *mux;
    tunnel_t        *next;
    line_t         **children;
    uint32_t         child_count;
    uint32_t         child_capacity;
    uint32_t         quiet_data;
    uint32_t         quiet_pauses;
    uint32_t         quiet_resumes;
    uint32_t         quiet_finishes;
    uint32_t         quiet_parent_payloads;
    uint32_t         quiet_parent_finishes;
} muxclient_capacity_fixture_t;

static muxclient_capacity_fixture_t *g_client_fixture = NULL;

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

static void fixtureTrackChild(muxclient_capacity_fixture_t *fixture, line_t *child_l)
{
    if (fixture->child_count == fixture->child_capacity)
    {
        uint32_t new_capacity = fixture->child_capacity == 0 ? kClientInitialChildren : fixture->child_capacity * 2U;
        line_t **new_children = memoryAllocate(sizeof(*new_children) * new_capacity);
        twfRequire(new_children != NULL, "failed to grow the MuxClient borrowed-child registry");
        if (fixture->child_count != 0)
        {
            memoryCopy(new_children, fixture->children, sizeof(*new_children) * fixture->child_count);
        }
        memoryFree(fixture->children);
        fixture->children       = new_children;
        fixture->child_capacity = new_capacity;
    }
    fixture->children[fixture->child_count++] = child_l;
}

static void fixtureSetup(muxclient_capacity_fixture_t *fixture, uint8_t mode, uint32_t fixed_count)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kClientTestBufferSize, kMuxFrameLength * 2U);

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->mux  = tunnelCreate(NULL, sizeof(muxclient_tstate_t) + sizeof(line_t *), sizeof(muxclient_lstate_t));
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->mux != NULL, "failed to create the MuxClient capacity fixture tunnel");
    tunnelBind(fixture->prev, fixture->mux);
    tunnelBind(fixture->mux, fixture->next);

    muxclient_tstate_t *ts            = tunnelGetState(fixture->mux);
    ts->concurrency_mode              = mode;
    ts->concurrency_duration          = 1000;
    ts->concurrency_capacity          = 2;
    ts->fixed_connections_count       = fixed_count;
    ts->child_buffer_limit            = kMuxDefaultChildBufferLimit;
    ts->child_buffer_pause_tolerance  = kMuxDefaultChildBufferPauseTolerance;
    ts->child_buffer_resume_threshold = kMuxDefaultChildBufferResumeThreshold;
    ts->parent_buffer_limit           = kMuxDefaultParentBufferLimit;
    ts->detached_buffer_limit         = kMuxMinimumDetachedBufferLimit;
    ts->detached_child_limit          = kMuxMinimumDetachedChildLimit;
    ts->max_children                  = 16;
    ts->workers_count                 = 1;
    ts->detached_child_counts         = memoryAllocateZero(sizeof(*ts->detached_child_counts));
    ts->detached_queued_charge         = memoryAllocateZero(sizeof(*ts->detached_queued_charge));
    twfRequire(ts->detached_child_counts != NULL && ts->detached_queued_charge != NULL,
               "failed to allocate MuxClient detached accounting");

    if (mode == kConcurrencyModeFixedConnectionsCount)
    {
        ts->fixed_parent_lines        = memoryAllocateZero(sizeof(*ts->fixed_parent_lines) * fixed_count);
        ts->fixed_next_parent_indexes = memoryAllocateZero(sizeof(*ts->fixed_next_parent_indexes));
        twfRequire(ts->fixed_parent_lines != NULL && ts->fixed_next_parent_indexes != NULL,
                   "failed to allocate MuxClient fixed-parent selection state");
    }

    fixture->chain                      = tunnelchainCreate(1);
    fixture->chain->sum_line_state_size = fixture->mux->lstate_size;
    tunnelchainFinalize(fixture->chain);
    fixture->mux->chain = fixture->chain;
    g_client_fixture    = fixture;
}

static line_t *fixtureOpenChild(muxclient_capacity_fixture_t *fixture)
{
    line_t *child_l = twfLineCreate(fixture->mux->lstate_size);
    fixtureTrackChild(fixture, child_l);
    muxclientTunnelUpStreamInit(fixture->mux, child_l);
    return child_l;
}

static void fixtureFinishChild(muxclient_capacity_fixture_t *fixture, line_t *child_l)
{
    muxclient_lstate_t *child_ls = lineGetState(child_l, fixture->mux);
    if (child_ls->l != NULL)
    {
        muxclientTunnelUpStreamFinish(fixture->mux, child_l);
    }
}

static void fixtureTeardown(muxclient_capacity_fixture_t *fixture)
{
    for (uint32_t i = 0; i < fixture->child_count; ++i)
    {
        line_t *child_l = fixture->children[i];
        fixtureFinishChild(fixture, child_l);
        twfRequireLineStateZeroed(child_l, fixture->mux, "MuxClient teardown retained borrowed-child state");
        twfLineDestroy(child_l);
    }

    muxclient_tstate_t *ts = tunnelGetState(fixture->mux);
    twfRequireEqualU32(ts->detached_child_counts[0], 0, "MuxClient fixture retained detached children");
    twfRequire(ts->detached_queued_charge[0] == 0, "MuxClient fixture retained detached bytes");
    muxclientTunnelOnWorkerStop(fixture->mux, 0, wwLifecycleProcessShutdown());

    twfRequireNoLeakedBuffers();
    tunnelchainDestroy(fixture->chain);
    memoryFree(ts->fixed_parent_lines);
    memoryFree(ts->fixed_next_parent_indexes);
    memoryFree(ts->detached_child_counts);
    memoryFree(ts->detached_queued_charge);
    memoryFree(fixture->children);
    tunnelDestroy(fixture->prev);
    tunnelDestroy(fixture->mux);
    tunnelDestroy(fixture->next);
    g_client_fixture = NULL;
    twfWorkerEnvTeardown(&fixture->env);
}

static void sendParentFrame(muxclient_capacity_fixture_t *fixture, line_t *parent_l, mux_cid_t cid, uint8_t flags,
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
    muxclientTunnelDownStreamPayload(fixture->mux, parent_l, frame);
}

static void caseCounterParentRetiresOnlyOnNextSelection(void)
{
    twfSetCase("MuxClient counter parent retires only when another child requests capacity");
    muxclient_capacity_fixture_t fixture;
    fixtureSetup(&fixture, kConcurrencyModeCounter, 0);
    muxclient_tstate_t *ts   = tunnelGetState(fixture.mux);
    ts->max_children         = 16;
    ts->concurrency_capacity = 2;

    line_t             *first_child  = fixtureOpenChild(&fixture);
    line_t             *second_child = fixtureOpenChild(&fixture);
    muxclient_lstate_t *first_ls     = lineGetState(first_child, fixture.mux);
    line_t             *first_parent = first_ls->parent->l;
    muxclient_lstate_t *parent_ls    = first_ls->parent;
    muxclient_lstate_t *second_ls    = lineGetState(second_child, fixture.mux);
    twfRequire(second_ls->parent == parent_ls, "counter capacity split children before exhaustion");
    twfRequire(! parent_ls->selection_retired && ts->unsatisfied_lines[0] == first_parent,
               "counter parent retired before another selection was needed");

    line_t             *third_child = fixtureOpenChild(&fixture);
    muxclient_lstate_t *third_ls    = lineGetState(third_child, fixture.mux);
    line_t             *new_parent  = third_ls->parent->l;
    twfRequire(parent_ls->selection_retired, "counter-exhausted parent was not retired on the next selection");
    twfRequire(new_parent != first_parent && ts->unsatisfied_lines[0] == new_parent,
               "counter mode selected its retired parent again");

    fixtureFinishChild(&fixture, first_child);
    twfRequireEqualU32(parent_ls->children_count, 1, "counter parent closed before its final child left");
    const uint32_t parent_finishes_before = fixture.trace.next_finish;
    fixtureFinishChild(&fixture, second_child);
    twfRequireEqualU32(fixture.trace.next_finish,
                       parent_finishes_before + 1U,
                       "retired counter parent did not close through the owned-parent path");
    twfRequire(ts->unsatisfied_lines[0] == new_parent, "retired parent close displaced the replacement selection");
    fixtureTeardown(&fixture);
}

static void caseTimerParentRetiresOnlyOnNextSelection(void)
{
    twfSetCase("MuxClient timer parent retires only when another child requests capacity");
    muxclient_capacity_fixture_t fixture;
    fixtureSetup(&fixture, kConcurrencyModeTimer, 0);
    muxclient_tstate_t *ts = tunnelGetState(fixture.mux);

    line_t             *first_child  = fixtureOpenChild(&fixture);
    muxclient_lstate_t *first_ls     = lineGetState(first_child, fixture.mux);
    muxclient_lstate_t *parent_ls    = first_ls->parent;
    line_t             *first_parent = parent_ls->l;
    parent_ls->creation_epoch        = 0;
    ts->concurrency_duration         = 1;
    twfRequire(! parent_ls->selection_retired && ts->unsatisfied_lines[0] == first_parent,
               "expired timer parent retired without a selection request");

    line_t             *second_child = fixtureOpenChild(&fixture);
    muxclient_lstate_t *second_ls    = lineGetState(second_child, fixture.mux);
    line_t             *new_parent   = second_ls->parent->l;
    twfRequire(parent_ls->selection_retired, "expired timer parent was not retired on the next selection");
    twfRequire(new_parent != first_parent && ts->unsatisfied_lines[0] == new_parent,
               "timer mode selected its retired parent again");

    const uint32_t parent_finishes_before = fixture.trace.next_finish;
    fixtureFinishChild(&fixture, first_child);
    twfRequireEqualU32(fixture.trace.next_finish,
                       parent_finishes_before + 1U,
                       "retired timer parent did not close when its final child left");
    fixtureTeardown(&fixture);
}

static void caseHardCapIndependentOfMode(uint8_t mode, const char *case_name)
{
    twfSetCase(case_name);
    muxclient_capacity_fixture_t fixture;
    fixtureSetup(&fixture, mode, 0);
    muxclient_tstate_t *ts   = tunnelGetState(fixture.mux);
    ts->max_children         = 2;
    ts->concurrency_capacity = UINT32_MAX;
    ts->concurrency_duration = UINT32_MAX;

    line_t             *first_child  = fixtureOpenChild(&fixture);
    line_t             *second_child = fixtureOpenChild(&fixture);
    muxclient_lstate_t *first_ls     = lineGetState(first_child, fixture.mux);
    muxclient_lstate_t *second_ls    = lineGetState(second_child, fixture.mux);
    muxclient_lstate_t *old_parent   = first_ls->parent;
    line_t             *old_parent_l = old_parent->l;
    twfRequire(second_ls->parent == old_parent, "the first two children did not share the selected parent");
    twfRequireEqualU32(old_parent->children_count, 2, "the selected parent did not reach the exact hard cap");
    twfRequire(! old_parent->selection_retired && ts->unsatisfied_lines[0] == old_parent_l,
               "the parent retired merely because its second child reached the cap");

    line_t             *third_child = fixtureOpenChild(&fixture);
    muxclient_lstate_t *third_ls    = lineGetState(third_child, fixture.mux);
    muxclient_lstate_t *new_parent  = third_ls->parent;
    twfRequire(old_parent->selection_retired, "the capped parent did not retire when new capacity was requested");
    twfRequire(new_parent != old_parent && ts->unsatisfied_lines[0] == new_parent->l,
               "the third child reused the capped or retired parent");

    fixtureFinishChild(&fixture, first_child);
    twfRequireEqualU32(old_parent->children_count, 1, "closing one old child changed the wrong parent count");
    line_t             *fourth_child = fixtureOpenChild(&fixture);
    muxclient_lstate_t *fourth_ls    = lineGetState(fourth_child, fixture.mux);
    twfRequire(fourth_ls->parent == new_parent && fourth_ls->parent != old_parent,
               "selection returned to a retired parent after it fell below the hard cap");

    const uint32_t parent_finishes_before = fixture.trace.next_finish;
    fixtureFinishChild(&fixture, second_child);
    twfRequireEqualU32(fixture.trace.next_finish,
                       parent_finishes_before + 1U,
                       "retired parent's final child did not close it through the owned-parent path");
    twfRequire(ts->unsatisfied_lines[0] == new_parent->l,
               "retired parent destruction displaced the current replacement parent");
    fixtureTeardown(&fixture);
}

static void caseFixedParentsBalanceRejectAndReuse(void)
{
    twfSetCase("MuxClient fixed mode balances, rejects when full, and reuses released capacity");
    muxclient_capacity_fixture_t fixture;
    fixtureSetup(&fixture, kConcurrencyModeFixedConnectionsCount, 3);
    muxclient_tstate_t *ts = tunnelGetState(fixture.mux);
    ts->max_children       = 2;

    line_t *admitted[6];
    for (uint32_t i = 0; i < ARRAY_SIZE(admitted); ++i)
    {
        admitted[i] = fixtureOpenChild(&fixture);
    }
    twfRequireEqualU32(fixture.trace.next_init, 3, "fixed mode did not create exactly its configured parent count");
    for (uint32_t i = 0; i < 3; ++i)
    {
        line_t *parent_l = ts->fixed_parent_lines[i];
        twfRequire(parent_l != NULL, "fixed mode left a configured parent slot empty");
        muxclient_lstate_t *parent_ls = lineGetState(parent_l, fixture.mux);
        twfRequireEqualU32(
            parent_ls->children_count, 2, "fixed mode did not balance children across least-loaded parents");
    }

    line_t *rejected = fixtureOpenChild(&fixture);
    twfRequireLineStateZeroed(rejected, fixture.mux, "all-full fixed mode initialized a rejected child");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "all-full fixed mode did not Finish the new borrowed child");
    twfRequireEqualU32(fixture.trace.next_init, 3, "all-full fixed mode created an extra parent");

    muxclient_lstate_t *released_child_ls = lineGetState(admitted[0], fixture.mux);
    line_t             *released_parent   = released_child_ls->parent->l;
    fixtureFinishChild(&fixture, admitted[0]);
    muxclient_lstate_t *released_parent_ls = lineGetState(released_parent, fixture.mux);
    twfRequireEqualU32(released_parent_ls->children_count, 1, "fixed parent lost more than the closed child");

    line_t             *replacement    = fixtureOpenChild(&fixture);
    muxclient_lstate_t *replacement_ls = lineGetState(replacement, fixture.mux);
    twfRequire(replacement_ls->parent->l == released_parent,
               "fixed mode did not choose the uniquely least-loaded parent");
    twfRequireEqualU32(released_parent_ls->children_count, 2, "fixed mode did not reuse released child capacity");
    twfRequireEqualU32(fixture.trace.next_init, 3, "fixed capacity reuse created another parent");
    fixtureTeardown(&fixture);
}

static void caseServerCloseTargetsOnlyIndexedChild(void)
{
    twfSetCase("MuxClient server Close targets only the indexed child and retains draining CIDs");
    muxclient_capacity_fixture_t fixture;
    fixtureSetup(&fixture, kConcurrencyModeFixedConnectionsCount, 1);
    muxclient_tstate_t *ts = tunnelGetState(fixture.mux);
    ts->max_children       = 8;

    line_t             *first      = fixtureOpenChild(&fixture);
    line_t             *second     = fixtureOpenChild(&fixture);
    line_t             *third      = fixtureOpenChild(&fixture);
    muxclient_lstate_t *first_ls   = lineGetState(first, fixture.mux);
    muxclient_lstate_t *second_ls  = lineGetState(second, fixture.mux);
    muxclient_lstate_t *third_ls   = lineGetState(third, fixture.mux);
    muxclient_lstate_t *parent_ls  = first_ls->parent;
    line_t             *parent_l   = parent_ls->l;
    const mux_cid_t     second_cid = second_ls->connection_id;
    const mux_cid_t     third_cid  = third_ls->connection_id;
    first_ls->open_frame_sent      = true;
    second_ls->open_frame_sent     = true;
    third_ls->open_frame_sent      = true;

    sendParentFrame(&fixture, parent_l, second_cid, kMuxFlagClose, 0);
    twfRequireLineStateZeroed(second, fixture.mux, "server Close retained the indexed borrowed child");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "server Close did not Finish exactly one borrowed child");
    twfRequireEqualU32(parent_ls->children_count, 2, "server Close changed sibling membership");
    twfRequire(muxclientFindChildByConnectionId(parent_ls, first_ls->connection_id) == first_ls,
               "server Close removed the first sibling");
    twfRequire(muxclientFindChildByConnectionId(parent_ls, third_cid) == third_ls,
               "server Close removed the third sibling");

    third_ls->paused = true;
    sendParentFrame(&fixture, parent_l, third_cid, kMuxFlagClose, 0);
    twfRequire(third_ls->close_state == kMuxClientChildClosePeerDraining,
               "paused server Close did not enter peer-draining state");
    twfRequire(muxclientFindChildByConnectionId(parent_ls, third_cid) == third_ls,
               "peer-draining client CID left the index before true leave");
    muxclientTunnelUpStreamResume(fixture.mux, third);
    twfRequireLineStateZeroed(third, fixture.mux, "peer-draining Resume did not finish the borrowed child");
    twfRequire(muxclientFindChildByConnectionId(parent_ls, third_cid) == NULL,
               "finished peer-draining CID remained indexed");
    twfRequireEqualU32(fixture.trace.prev_finish, 2, "peer-draining child did not Finish exactly once");

    sendParentFrame(&fixture, parent_l, first_ls->connection_id, kMuxFlagData, 0xA7);
    twfRequireEqualU32(fixture.trace.prev_payload, 1, "surviving sibling stopped receiving Data");
    fixtureTeardown(&fixture);
}

static uint8_t dispatchByte(mux_cid_t cid)
{
    return (uint8_t) ((cid * 33U + 7U) & 0xFFU);
}

static void quietChildPayload(tunnel_t *prev, line_t *child_l, sbuf_t *buf)
{
    discard                       prev;
    muxclient_capacity_fixture_t *fixture  = g_client_fixture;
    muxclient_lstate_t           *child_ls = lineGetState(child_l, fixture->mux);
    twfRequireEqualU32(sbufGetLength(buf), 1, "production hash dispatch delivered the wrong Data length");
    twfRequire(((const uint8_t *) sbufGetRawPtr(buf))[0] == dispatchByte(child_ls->connection_id),
               "production hash dispatch delivered Data to the wrong CID");
    ++fixture->quiet_data;
    lineReuseBuffer(child_l, buf);
}

static void quietChildPause(tunnel_t *prev, line_t *child_l)
{
    discard prev;
    discard child_l;
    ++g_client_fixture->quiet_pauses;
}

static void quietChildResume(tunnel_t *prev, line_t *child_l)
{
    discard prev;
    discard child_l;
    ++g_client_fixture->quiet_resumes;
}

static void quietChildFinish(tunnel_t *prev, line_t *child_l)
{
    discard prev;
    twfRequireLineStateZeroed(
        child_l, g_client_fixture->mux, "production Close notified the child before removing its index state");
    ++g_client_fixture->quiet_finishes;
}

static void quietParentPayload(tunnel_t *next, line_t *parent_l, sbuf_t *buf)
{
    discard next;
    ++g_client_fixture->quiet_parent_payloads;
    lineReuseBuffer(parent_l, buf);
}

static void quietParentFinish(tunnel_t *next, line_t *parent_l)
{
    discard next;
    discard parent_l;
    ++g_client_fixture->quiet_parent_finishes;
}

static void caseProductionHashDispatchAtScale(void)
{
    twfSetCase("MuxClient production parser dispatches thousands of non-sequential CIDs through its hash index");
    muxclient_capacity_fixture_t fixture;
    fixtureSetup(&fixture, kConcurrencyModeFixedConnectionsCount, 1);
    muxclient_tstate_t *ts = tunnelGetState(fixture.mux);
    ts->max_children       = kClientDispatchChildren + 1U;

    fixture.prev->fnPayloadD = quietChildPayload;
    fixture.prev->fnPauseD   = quietChildPause;
    fixture.prev->fnResumeD  = quietChildResume;
    fixture.prev->fnFinD     = quietChildFinish;
    fixture.next->fnPayloadU = quietParentPayload;
    fixture.next->fnFinU     = quietParentFinish;

    line_t *selector = twfLineCreate(fixture.mux->lstate_size);
    line_t *parent_l = muxclientGetParentLineForNewChild(fixture.mux, selector);
    twfRequire(parent_l != NULL, "fixed selection did not create its production parent");
    twfLineDestroy(selector);
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, fixture.mux);

    line_t **children = memoryAllocate(sizeof(*children) * kClientDispatchChildren);
    twfRequire(children != NULL, "failed to allocate the scalable child pointer set");
    for (uint32_t i = 0; i < kClientDispatchChildren; ++i)
    {
        const mux_cid_t cid = (i * 104729U) + 17U;
        children[i]         = twfLineCreate(fixture.mux->lstate_size);
        fixtureTrackChild(&fixture, children[i]);
        muxclient_lstate_t *child_ls = lineGetState(children[i], fixture.mux);
        muxclientLinestateInitialize(child_ls, children[i], true, cid);
        child_ls->open_frame_sent = true;
        muxclientJoinConnection(parent_ls, child_ls);
    }
    twfRequireEqualU32(parent_ls->children_count, kClientDispatchChildren, "scalable setup did not publish every CID");
    twfRequireEqualU32((uint32_t) muxclient_child_map_t_size(&parent_ls->parent_state->child_map),
                       kClientDispatchChildren,
                       "scalable setup list/map counts disagree");

    uint32_t flow_cases = 0;
    for (uint32_t i = 0; i < kClientDispatchChildren; ++i)
    {
        muxclient_lstate_t *child_ls = lineGetState(children[i], fixture.mux);
        sendParentFrame(
            &fixture, parent_l, child_ls->connection_id, kMuxFlagData, dispatchByte(child_ls->connection_id));
        if ((i % 257U) == 0)
        {
            sendParentFrame(&fixture, parent_l, child_ls->connection_id, kMuxFlagFlowPause, 0);
            sendParentFrame(&fixture, parent_l, child_ls->connection_id, kMuxFlagFlowResume, 0);
            ++flow_cases;
        }
    }
    twfRequireEqualU32(fixture.quiet_data, kClientDispatchChildren, "production Data hash dispatch skipped a CID");
    twfRequireEqualU32(fixture.quiet_pauses, flow_cases, "production FlowPause hash dispatch skipped a CID");
    twfRequireEqualU32(fixture.quiet_resumes, flow_cases, "production FlowResume hash dispatch skipped a CID");

    uint32_t closed = 0;
    for (uint32_t i = 0; i < kClientDispatchChildren; i += 5U)
    {
        muxclient_lstate_t *child_ls = lineGetState(children[i], fixture.mux);
        sendParentFrame(&fixture, parent_l, child_ls->connection_id, kMuxFlagClose, 0);
        ++closed;
    }
    twfRequireEqualU32(fixture.quiet_finishes, closed, "production Close hash dispatch finished the wrong count");
    twfRequireEqualU32(parent_ls->children_count,
                       kClientDispatchChildren - closed,
                       "production Close hash dispatch changed the wrong membership count");
    twfRequireEqualU32((uint32_t) muxclient_child_map_t_size(&parent_ls->parent_state->child_map),
                       kClientDispatchChildren - closed,
                       "production Close hash dispatch broke list/map agreement");

    memoryFree(children);
    fixtureTeardown(&fixture);
}

int main(void)
{
    caseCounterParentRetiresOnlyOnNextSelection();
    caseTimerParentRetiresOnlyOnNextSelection();
    caseHardCapIndependentOfMode(kConcurrencyModeCounter,
                                 "MuxClient counter mode enforces max_children independently of exhaustion");
    caseHardCapIndependentOfMode(kConcurrencyModeTimer,
                                 "MuxClient timer mode enforces max_children independently of duration");
    caseFixedParentsBalanceRejectAndReuse();
    caseServerCloseTargetsOnlyIndexedChild();
    caseProductionHashDispatchAtScale();

    printf("muxclient_capacity_dispatch_test: all cases passed\n");
    return 0;
}
