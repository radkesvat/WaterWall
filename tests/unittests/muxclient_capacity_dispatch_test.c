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
    twf_line_pool_t  child_lines;
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
    out[0] = (uint8_t) (length >> 16U);
    out[1] = (uint8_t) (length >> 8U);
    out[2] = (uint8_t) length;
    out[3] = flags;
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
    lineRef(child_l);
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
    ts->child_buffer_resume_threshold = kMuxDefaultChildBufferResumeThreshold;
    ts->parent_buffer_limit           = kMuxDefaultParentBufferLimit;
    ts->parent_write_pause_threshold  = kMuxDefaultParentWritePauseThreshold;
    ts->parent_write_resume_threshold = kMuxDefaultParentWriteResumeThreshold;
    ts->parent_write_limit            = kMuxDefaultParentWriteLimit;
    ts->detached_buffer_limit         = kMuxMinimumDetachedBufferLimit;
    ts->detached_child_limit          = kMuxMinimumDetachedChildLimit;
    ts->max_children                  = 16;
    ts->workers_count                 = 1;
    ts->worker_states                 = memoryAllocateZero(sizeof(*ts->worker_states));
    ts->detached_child_counts         = memoryAllocateZero(sizeof(*ts->detached_child_counts));
    ts->detached_queued_charge        = memoryAllocateZero(sizeof(*ts->detached_queued_charge));
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
    twfLinePoolSetup(&fixture->child_lines, fixture->mux->lstate_size, kClientDispatchChildren * 2U);
    g_client_fixture    = fixture;
}

static line_t *fixtureOpenChild(muxclient_capacity_fixture_t *fixture)
{
    line_t *child_l = twfLinePoolCreateLine(&fixture->child_lines);
    fixtureTrackChild(fixture, child_l);
    muxclientTunnelUpStreamInit(fixture->mux, child_l);
    return child_l;
}

static void fixtureFinishChild(muxclient_capacity_fixture_t *fixture, line_t *child_l)
{
    muxclient_lstate_t *child_ls = lineGetState(child_l, fixture->mux);
    if (lineIsAlive(child_l) && child_ls->l != NULL)
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
        if (lineIsAlive(child_l))
        {
            lineDestroy(child_l);
        }
        lineUnref(child_l);
    }

    muxclient_tstate_t *ts = tunnelGetState(fixture->mux);
    twfRequireEqualU32(ts->detached_child_counts[0], 0, "MuxClient fixture retained detached children");
    twfRequire(ts->detached_queued_charge[0] == 0, "MuxClient fixture retained detached bytes");
    muxclientTunnelOnWorkerStop(fixture->mux, 0, wwLifecycleProcessShutdown());

    twfRequireNoLeakedBuffers();
    tunnelchainDestroy(fixture->chain);
    memoryFree(ts->fixed_parent_lines);
    memoryFree(ts->fixed_next_parent_indexes);
    memoryFree(ts->worker_states);
    memoryFree(ts->detached_child_counts);
    memoryFree(ts->detached_queued_charge);
    memoryFree(fixture->children);
    twfLinePoolTeardown(&fixture->child_lines);
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
    first_ls->open_frame_submitted  = true;
    second_ls->open_frame_submitted = true;
    third_ls->open_frame_submitted  = true;

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
        children[i]         = twfLinePoolCreateLine(&fixture.child_lines);
        fixtureTrackChild(&fixture, children[i]);
        muxclient_lstate_t *child_ls = lineGetState(children[i], fixture.mux);
        muxclientLinestateInitialize(fixture.mux, child_ls, children[i], true, cid);
        child_ls->open_frame_submitted = true;
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

static line_t *g_shutdown_other_parent;

static void shutdownSourceFinish(tunnel_t *t, line_t *child_l)
{
    twfPrevFinish(t, child_l);
    twfRequireLineStateZeroed(child_l, g_client_fixture->mux, "source Finish observed live MUX state");
    lineDestroy(child_l);
    if (g_shutdown_other_parent != NULL)
    {
        line_t *other           = g_shutdown_other_parent;
        g_shutdown_other_parent = NULL;
        muxclientTunnelDownStreamFinish(g_client_fixture->mux, other);
    }
}

static void shutdownInitFinish(tunnel_t *t, line_t *parent_l)
{
    discard t;
    muxclientTunnelDownStreamFinish(g_client_fixture->mux, parent_l);
}

static void caseShutdownInventory(uint8_t mode, unsigned order, unsigned reentrant)
{
    twfSetCase("MuxClient drains real parents independently of selection and source order");
    muxclient_capacity_fixture_t fixture;
    fixtureSetup(&fixture, mode, mode == kConcurrencyModeFixedConnectionsCount ? 3 : 0);
    fixture.prev->fnFinD         = shutdownSourceFinish;
    muxclient_tstate_t *ts       = tunnelGetState(fixture.mux);
    ts->concurrency_capacity     = 1;
    line_t             *first    = fixtureOpenChild(&fixture);
    muxclient_lstate_t *first_ls = lineGetState(first, fixture.mux);
    line_t             *parent_a = first_ls->parent->l;
    lineRef(parent_a);
    if (mode == kConcurrencyModeTimer)
    {
        first_ls->parent->creation_epoch = 0;
        ts->concurrency_duration         = 1;
    }
    line_t             *second    = fixtureOpenChild(&fixture);
    muxclient_lstate_t *second_ls = lineGetState(second, fixture.mux);
    line_t             *parent_b  = second_ls->parent->l;
    lineRef(parent_b);
    twfRequire(parent_a != parent_b, "shutdown fixture did not create distinct parents");
    if (mode != kConcurrencyModeFixedConnectionsCount)
    {
        twfRequire(first_ls->parent->selection_retired, "old parent was not retired");
        twfRequire(first_ls->parent->parent_state->owned, "retirement removed parent ownership");
    }
    first_ls->paused  = true;
    second_ls->paused = true;
    sendParentFrame(&fixture, parent_a, first_ls->connection_id, kMuxFlagData, 7);
    sendParentFrame(&fixture, parent_b, second_ls->connection_id, kMuxFlagData, 9);
    memoryZero(&fixture.trace, sizeof(fixture.trace));
    muxclientTunnelOnWorkerQuiesce(fixture.mux, 0, wwLifecycleProcessShutdown());
    if (order == 1)
    {
        fixtureFinishChild(&fixture, first);
        lineDestroy(first);
        fixtureFinishChild(&fixture, second);
        lineDestroy(second);
    }
    else if (order == 2)
    {
        muxclientTunnelDownStreamFinish(fixture.mux, parent_a);
    }
    if (reentrant)
    {
        g_shutdown_other_parent = reentrant == 2 ? parent_b : parent_a;
    }
    muxclientTunnelOnWorkerStop(fixture.mux, 0, wwLifecycleProcessShutdown());
    twfRequire(! lineIsAlive(parent_a) && ! lineIsAlive(parent_b), "owner drain left a parent alive");
    twfRequire(! lineIsAlive(first) && ! lineIsAlive(second), "source Finish left borrowed children alive");
    twfRequire(ts->worker_states[0].owned_parents == NULL, "owner inventory survived drain");
    twfRequire(ts->unsatisfied_lines[0] == NULL, "selected parent survived drain");
    twfRequireEqualU32(fixture.trace.prev_finish, order == 1 ? 0 : 2, "source Finish reflected or repeated");
    twfRequireEqualU32(fixture.trace.next_finish,
                       (mode == kConcurrencyModeFixedConnectionsCount ? 3U : 2U) - (order == 2 ? 1U : 0U) -
                           (reentrant ? 1U : 0U),
                       "parent Finish reflected or repeated");
    twfRequireEqualU32(fixture.trace.next_payload + fixture.trace.prev_payload, 0, "shutdown emitted Payload");
    for (uint32_t i = 0; i < fixture.trace.len; ++i)
    {
        twfRequire(fixture.trace.seq[i] == 'f' || fixture.trace.seq[i] == 'F', "shutdown emitted non-Finish work");
    }
    muxclientTunnelOnWorkerStop(fixture.mux, 0, wwLifecycleProcessShutdown());
    lineUnref(parent_a);
    lineUnref(parent_b);
    fixtureTeardown(&fixture);
}

static void caseInitClosesInventoriedParent(void)
{
    twfSetCase("MuxClient re-entrant Init failure removes selection and ownership");
    muxclient_capacity_fixture_t fixture;
    fixtureSetup(&fixture, kConcurrencyModeCounter, 0);
    fixture.next->fnInitU     = shutdownInitFinish;
    fixture.prev->fnFinD      = shutdownSourceFinish;
    line_t             *child = fixtureOpenChild(&fixture);
    muxclient_tstate_t *ts    = tunnelGetState(fixture.mux);
    twfRequire(ts->worker_states[0].owned_parents == NULL && ts->unsatisfied_lines[0] == NULL,
               "Init failure retained parent publication");
    twfRequire(! lineIsAlive(child), "failed Init did not finish source child");
    fixtureTeardown(&fixture);
}

static void caseWorkerDrainIsLocal(void)
{
    twfSetCase("MuxClient drains only the supplied worker without touching another worker inventory");
    twf_worker_env_t env;
    twfWorkerEnvSetup(&env, kClientTestBufferSize, kMuxFrameLength * 2U);
    master_pool_t *large       = masterpoolCreateWithCapacity(8);
    master_pool_t *small       = masterpoolCreateWithCapacity(8);
    master_pool_t *medium      = masterpoolCreateWithCapacity(8);
    master_pool_t *splice      = masterpoolCreateWithCapacity(8);
    buffer_pool_t *second_pool =
        bufferpoolCreate(large, medium, small, splice, 4, kClientTestBufferSize, MEDIUM_BUFFER_SIZE_RAM_HIGH, 1024);
    bufferpoolUpdateAllocationPaddings(
        second_pool, kMuxFrameLength * 2U, kMuxFrameLength * 2U, kMuxFrameLength * 2U, kMuxFrameLength * 2U);
    wloop_t       *second_loop   = wloopCreate(WLOOP_FLAG_AUTO_FREE, second_pool, 1);
    buffer_pool_t *pools[2]      = {env.pool, second_pool};
    wloop_t       *loops[2]      = {env.loop, second_loop};
    worker_t       workers[2]    = {env.worker,
                                    {.wid = 1, .buffer_pool = second_pool, .loop = second_loop, .has_event_loop = true}};
    GSTATE.workers_count         = 3;
    GSTATE.workers               = workers;
    GSTATE.shortcut_buffer_pools = pools;
    GSTATE.shortcut_loops        = loops;
    twf_trace_t trace            = {0};
    tunnel_t   *mux = tunnelCreate(NULL, sizeof(muxclient_tstate_t) + 2 * sizeof(line_t *), sizeof(muxclient_lstate_t));
    tunnel_t   *next = twfCreateNextTunnel(&trace);
    tunnelBind(mux, next);
    muxclient_tstate_t *ts = tunnelGetState(mux);
    ts->workers_count      = 2;
    ts->worker_states      = memoryAllocateZero(2 * sizeof(*ts->worker_states));
    ts->concurrency_mode   = kConcurrencyModeCounter;
    twf_line_pool_t lines[2];
    twfLinePoolSetup(&lines[0], mux->lstate_size, 8);
    twfLinePoolSetup(&lines[1], mux->lstate_size, 8);
    generic_pool_t *line_pools[2] = {lines[0].pools[0], lines[1].pools[0]};
    line_t         *parents[2];
    for (wid_t wid = 0; wid < 2; ++wid)
    {
        testWorkerBindWID(wid);
        parents[wid] = lineCreateForWorker(wid, line_pools, wid);
        lineRef(parents[wid]);
        muxclient_lstate_t *parent = lineGetState(parents[wid], mux);
        muxclientLinestateInitialize(mux, parent, parents[wid], false, 0);
        muxclientRegisterParent(ts, parent);
        ts->unsatisfied_lines[wid] = parents[wid];
    }
    testWorkerBindWID(0);
    muxclientTunnelOnWorkerStop(mux, 0, wwLifecycleProcessShutdown());
    twfRequire(! lineIsAlive(parents[0]) && lineIsAlive(parents[1]), "worker 0 drained another worker's child");
    twfRequire(ts->worker_states[1].owned_parents != NULL && ! ts->worker_states[1].quiescing,
               "worker 0 changed worker 1 state");
    muxclientTunnelOnWorkerStop(mux, 0, wwLifecycleProcessShutdown());
    for (wid_t wid = 0; wid < 2; ++wid)
    {
        testWorkerBindWID(wid);
        muxclientTunnelOnWorkerStop(mux, wid, wwLifecycleProcessShutdown());
        twfRequire(! lineIsAlive(parents[wid]), "worker drain retained a child");
        lineUnref(parents[wid]);
        twfRequireEqualU32(masterpoolGetCheckedOut(lines[wid].master), 0, "worker retained pooled lines");
        twfLinePoolTeardown(&lines[wid]);
    }
    mux->onStop(mux, wwLifecycleProcessShutdown());
    memoryFree(ts->worker_states);
    tunnelDestroy(mux);
    tunnelDestroy(next);
    wloopDestroy(&second_loop);
    bufferpoolDestroy(second_pool);
    masterpoolDestroy(large);
    masterpoolDestroy(small);
    masterpoolDestroy(medium);
    masterpoolDestroy(splice);
    GSTATE.workers_count         = 2;
    GSTATE.workers               = &env.worker;
    GSTATE.shortcut_buffer_pools = env.pool_shortcut;
    GSTATE.shortcut_loops        = env.loop_shortcut;
    testWorkerBindWID(0);
    twfWorkerEnvTeardown(&env);
}

static bool output_est_active;
static bool output_close_in_est;
static bool output_release_in_est;

static void outputEstProducer(tunnel_t *prev, line_t *child_l)
{
    discard prev;
    output_est_active = true;
    sbuf_t *buf       = bufferpoolGetSmallBuffer(g_client_fixture->env.pool);
    sbufSetLength(buf, 1);
    muxclientTunnelUpStreamPayload(g_client_fixture->mux, child_l, buf);
    if (output_release_in_est)
    {
        muxclient_lstate_t *child  = lineGetState(child_l, g_client_fixture->mux);
        child->parent_write_paused = true;
        muxclientTunnelDownStreamResume(g_client_fixture->mux, child->parent->l);
        twfRequire(child->parent_write_paused, "starting child was visited during release fanout");
    }
    if (output_close_in_est)
    {
        muxclientTunnelUpStreamFinish(g_client_fixture->mux, child_l);
        lineDestroy(child_l);
    }
    output_est_active = false;
}

static void outputInitSafePause(tunnel_t *prev, line_t *child_l)
{
    twfRequire(! output_est_active, "parent pressure reached producer before Est completed");
    quietChildPause(prev, child_l);
}

static void caseNewChildInheritsOutputGate(bool close_in_est, bool release_in_est)
{
    twfSetCase("MuxClient child joins a gated parent and safely produces or closes during Est");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, kConcurrencyModeCounter, 0);
    muxclient_tstate_t *ts           = tunnelGetState(f.mux);
    ts->concurrency_capacity         = 32;
    ts->parent_write_pause_threshold = 1;
    ts->parent_write_resume_threshold = 0;
    f.prev->fnPauseD                 = outputInitSafePause;
    line_t             *first        = fixtureOpenChild(&f);
    muxclient_lstate_t *child        = lineGetState(first, f.mux);
    line_t             *parent       = child->parent->l;
    muxclientTunnelDownStreamPause(f.mux, parent);
    sbuf_t *buf = bufferpoolGetSmallBuffer(f.env.pool);
    sbufSetLength(buf, 1);
    muxclientTunnelUpStreamPayload(f.mux, first, buf);
    f.prev->fnEstD      = outputEstProducer;
    output_close_in_est = close_in_est;
    output_release_in_est = release_in_est;
    line_t *second      = fixtureOpenChild(&f);
    if (close_in_est)
        twfRequire(! lineIsAlive(second), "reentrant Est Finish was lost");
    else
    {
        muxclient_lstate_t *second_state = lineGetState(second, f.mux);
        twfRequire(second_state->parent == child->parent && second_state->parent_write_paused == ! release_in_est,
                   "new child missed parent gate");
        twfRequire(f.quiet_pauses == (release_in_est ? 1U : 2U), "new child received incorrect Pause count");
    }
    muxclientTunnelDownStreamResume(f.mux, parent);
    fixtureTeardown(&f);
}

static void caseIdleParentWaitsForOutput(uint8_t mode, bool stop)
{
    twfSetCase("zero-child parents retain ordered final output until drain or owner Stop");
    muxclient_capacity_fixture_t f;
    fixtureSetup(&f, mode, mode == kConcurrencyModeFixedConnectionsCount ? 1 : 0);
    muxclient_tstate_t *ts           = tunnelGetState(f.mux);
    ts->concurrency_capacity         = 1;
    line_t             *child        = fixtureOpenChild(&f);
    muxclient_lstate_t *child_state  = lineGetState(child, f.mux);
    muxclient_lstate_t *parent_state = child_state->parent;
    line_t             *parent       = parent_state->l;
    lineRef(parent);
    if (mode == kConcurrencyModeTimer)
    {
        parent_state->creation_epoch = 0;
        ts->concurrency_duration     = 1;
    }
    muxclientTunnelDownStreamPause(f.mux, parent);
    sbuf_t *buf = bufferpoolGetSmallBuffer(f.env.pool);
    sbufSetLength(buf, 1);
    muxclientTunnelUpStreamPayload(f.mux, child, buf);
    fixtureFinishChild(&f, child);
    twfRequire(lineIsAlive(parent) && parent_state->children_count == 0 && parent_state->parent_state->owned &&
                   bufferqueueGetBufCount(&parent_state->parent_state->output.pending) == 2,
               "last-child Finish lost parent output ownership");
    twfRequire(f.trace.next_payload == 0, "final Close bypassed parent Pause");
    if (mode != kConcurrencyModeFixedConnectionsCount)
        twfRequire(ts->unsatisfied_lines[0] == NULL && parent_state->selection_retired,
                   "pending idle parent stayed selectable");
    if (stop)
    {
        muxclientTunnelOnWorkerStop(f.mux, 0, wwLifecycleProcessShutdown());
        twfRequire(! lineIsAlive(parent) && f.trace.next_payload == 0, "Stop waited for Resume or emitted output");
    }
    else
    {
        muxclientTunnelDownStreamResume(f.mux, parent);
        twfRequire(f.trace.next_payload == 2, "idle parent lost final ordered output");
        twfRequire(lineIsAlive(parent) == (mode == kConcurrencyModeFixedConnectionsCount),
                   "idle drain failed to close exhausted parent or closed reusable fixed parent");
    }
    lineUnref(parent);
    fixtureTeardown(&f);
}

int main(void)
{
    caseNewChildInheritsOutputGate(false, false);
    caseNewChildInheritsOutputGate(false, true);
    caseNewChildInheritsOutputGate(true, false);
    caseIdleParentWaitsForOutput(kConcurrencyModeCounter, false);
    caseIdleParentWaitsForOutput(kConcurrencyModeTimer, false);
    caseIdleParentWaitsForOutput(kConcurrencyModeFixedConnectionsCount, false);
    caseIdleParentWaitsForOutput(kConcurrencyModeCounter, true);
    caseIdleParentWaitsForOutput(kConcurrencyModeTimer, true);
    caseIdleParentWaitsForOutput(kConcurrencyModeFixedConnectionsCount, true);
    caseWorkerDrainIsLocal();
    caseShutdownInventory(kConcurrencyModeCounter, 0, 1);
    caseShutdownInventory(kConcurrencyModeCounter, 0, 2);
    caseShutdownInventory(kConcurrencyModeTimer, 1, false);
    caseShutdownInventory(kConcurrencyModeFixedConnectionsCount, 2, false);
    caseInitClosesInventoriedParent();
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
