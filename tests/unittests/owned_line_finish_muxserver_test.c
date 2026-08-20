/*
 * The owned-line Finish postcondition, on an internal owner.
 *
 * MuxServer is the interesting shape: it creates every child line but borrows
 * the parent connection line from whatever adapter accepted it. One Finish
 * handler therefore has to leave one line dead and the other untouched, and the
 * caller has to be able to tell which happened.
 *
 * Every case runs the owner's Finish under an outer lineLock(), which is the
 * frame the contract exists for: it keeps the allocation readable past the
 * owner's lineDestroy() so lineIsAlive() can be checked at all, and it is what a
 * real re-entrant caller holds.
 */
#include "MuxServer/structure.h"

#include "tunnel_line_failure_harness.h"

enum
{
    kTestLargeBufferSize = 64u * 1024u,
    kTestChildCid        = 7,
    kTestLinePoolItems   = 8
};

typedef struct muxserver_fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  lines;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *mux;
    tunnel_t        *next;
    line_t          *parent_l;
    line_t          *child_l;
} muxserver_fixture_t;

static void fixtureSetup(muxserver_fixture_t *fixture)
{
    memoryZero(&fixture->trace, sizeof(fixture->trace));
    // The Close frame this close path writes is prepended into the buffer's left
    // padding, exactly as the chain's summed required_padding_left would allow.
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, kMuxFrameLength * 2);

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->mux  = tunnelCreate(
        NULL, sizeof(muxserver_tstate_t) + sizeof(muxserver_detached_registry_t), sizeof(muxserver_lstate_t));
    twfRequire(fixture->mux != NULL, "failed to create the MuxServer tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);

    tunnelBind(fixture->prev, fixture->mux);
    tunnelBind(fixture->mux, fixture->next);

    muxserver_tstate_t *ts            = tunnelGetState(fixture->mux);
    ts->child_buffer_limit            = kMuxDefaultChildBufferLimit;
    ts->child_buffer_pause_tolerance  = kMuxDefaultChildBufferPauseTolerance;
    ts->child_buffer_resume_threshold = kMuxDefaultChildBufferResumeThreshold;
    ts->parent_buffer_limit           = kMuxDefaultParentBufferLimit;
    ts->detached_buffer_limit         = kMuxMinimumDetachedBufferLimit;
    ts->detached_child_limit          = kMuxMinimumDetachedChildLimit;
    ts->workers_count                 = 1;

    // Real pooled lines: lineDestroy() returns a line to line->pools[wid], so the
    // postcondition cannot be driven with a bare allocation.
    twfLinePoolSetup(&fixture->lines, fixture->mux->lstate_size, kTestLinePoolItems);
    fixture->parent_l = twfLinePoolCreateLine(&fixture->lines);
    fixture->child_l  = twfLinePoolCreateLine(&fixture->lines);

    muxserver_lstate_t *parent_ls = lineGetState(fixture->parent_l, fixture->mux);
    muxserver_lstate_t *child_ls  = lineGetState(fixture->child_l, fixture->mux);

    muxserverLinestateInitialize(parent_ls, fixture->parent_l, false, 0);
    muxserverLinestateInitialize(child_ls, fixture->child_l, true, kTestChildCid);
    muxserverJoinConnection(parent_ls, child_ls);
}

/**
 * Close whatever the case left alive. The parent is borrowed, so this stands in
 * for the adapter that really owns it.
 */
static void fixtureTeardown(muxserver_fixture_t *fixture)
{
    if (lineIsAlive(fixture->parent_l))
    {
        muxserver_lstate_t *parent_ls = lineGetState(fixture->parent_l, fixture->mux);
        if (parent_ls->l != NULL)
        {
            muxserverLinestateDestroy(parent_ls);
        }
        lineDestroy(fixture->parent_l);
    }

    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&fixture->lines);
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->mux);
    tunnelDestroy(fixture->prev);
}

// ---------------------------------------------------------------------------
// The owned child dies; the borrowed parent does not
// ---------------------------------------------------------------------------

static void caseInternalOwnerFinishKillsChildOnly(void)
{
    twfSetCase("muxserver downstream Finish closes the owned child line");

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture);

    muxserver_lstate_t *parent_ls = lineGetState(fixture.parent_l, fixture.mux);
    twfRequireEqualU32(parent_ls->children_count, 1, "the fixture must start with one attached child");

    // The child's next side finished us, so this is the owner reacting to a real
    // downstream Finish.
    twfRunOwnerFinish(fixture.mux, fixture.child_l, muxserverTunnelDownStreamFinish, "muxserverTunnelDownStreamFinish");

    // Nothing may be reflected toward the side that finished us.
    twfRequireEqualU32(fixture.trace.next_finish, 0, "a received downstream Finish must not be reflected upstream");
    twfRequireEqualU32(fixture.trace.next_payload, 0, "a received downstream Finish must not answer upstream");

    // The peer still learns about the close, over the borrowed parent line.
    twfRequireEqualU32(fixture.trace.prev_payload, 1, "the mux Close frame must be written to the parent line");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "closing one child must not finish the parent connection");

    // The borrowed parent is untouched: still alive, still holding its own state,
    // and no longer counting the child.
    twfRequire(lineIsAlive(fixture.parent_l), "the borrowed parent line must survive an owned child's close");
    twfRequire(parent_ls->l == fixture.parent_l, "the borrowed parent's line state must survive");
    twfRequireEqualU32(parent_ls->children_count, 0, "the closed child must be unlinked from its parent");
    twfRequire(parent_ls->child_next == NULL, "the closed child must be unlinked from the sibling list");

    twfRequireOwnedLineReclaimed(fixture.child_l, "muxserverTunnelDownStreamFinish");
    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// A parent teardown closes its owned children the same way
// ---------------------------------------------------------------------------

static void caseParentFinishKillsOwnedChildren(void)
{
    twfSetCase("muxserver parent Finish closes every owned child line");

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture);

    // Hold the child the way a suspended frame would, then finish the parent from
    // its prev side. The parent is borrowed here, so only the child may die.
    lineLock(fixture.child_l);
    muxserverTunnelUpStreamFinish(fixture.mux, fixture.parent_l);

    twfRequire(! lineIsAlive(fixture.child_l),
               "muxserverTunnelUpStreamFinish returned with an owned child line still alive");
    twfRequireLineStateZeroed(fixture.child_l, fixture.mux, "the closed child's line state must be destroyed");

    // The parent's prev finished us, so the child's still-open next side is the
    // only direction that may be told.
    twfRequireEqualU32(fixture.trace.next_finish, 1, "the owned child's next side must be finished exactly once");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "a received upstream Finish must not be reflected downstream");

    twfRequire(lineIsAlive(fixture.parent_l), "MuxServer borrows the parent line and must not destroy it");
    twfRequireLineStateZeroed(fixture.parent_l, fixture.mux, "the parent's own line state must still be destroyed");

    twfRequireOwnedLineReclaimed(fixture.child_l, "muxserverTunnelUpStreamFinish");

    // The parent's line state is already gone, so release it directly.
    lineDestroy(fixture.parent_l);
    twfRequireNoLeakedBuffers();
    twfLinePoolTeardown(&fixture.lines);
    tunnelDestroy(fixture.next);
    tunnelDestroy(fixture.mux);
    tunnelDestroy(fixture.prev);
}

// ---------------------------------------------------------------------------
// A nested path that already killed the line is not destroyed twice
// ---------------------------------------------------------------------------

static void caseNestedDestroyIsNotRepeated(void)
{
    twfSetCase("muxserver owner close tolerates an already dead child line");

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture);

    muxserver_lstate_t *parent_ls = lineGetState(fixture.parent_l, fixture.mux);
    muxserver_lstate_t *child_ls  = lineGetState(fixture.child_l, fixture.mux);

    // Stand in for a nested frame that already closed this child: the line is
    // logically dead but the outer reference keeps it readable, which is the exact
    // state the owner's `if (lineIsAlive(...))` guard exists for.
    lineLock(fixture.child_l);
    lineDestroy(fixture.child_l);
    twfRequire(! lineIsAlive(fixture.child_l), "the fixture must reach the owner with the child already dead");

    muxserverCloseChildKeepParent(fixture.mux, fixture.parent_l, parent_ls, child_ls, false);

    twfRequireLineStateZeroed(fixture.child_l, fixture.mux, "the child's line state must still be destroyed");
    twfRequireEqualU32(parent_ls->children_count, 0, "the child must still be unlinked from its parent");
    twfRequire(lineIsAlive(fixture.parent_l), "the borrowed parent must survive");

    // A second lineDestroy() would have dropped this reference too and handed the
    // allocation back to the pool underneath us.
    twfRequireOwnedLineReclaimed(fixture.child_l, "muxserverCloseChildKeepParent");
    fixtureTeardown(&fixture);
}

static sbuf_t *makeMuxserverQueuedPayload(muxserver_fixture_t *fixture, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetLargeBuffer(fixture->env.pool);
    buf         = sbufReserveSpace(buf, length);
    sbufSetLength(buf, length);
    memorySet(sbufGetMutablePtr(buf), (uint8_t) length, length);
    return buf;
}

static void queueTwoPausedServerPayloads(muxserver_fixture_t *fixture, uint32_t first_len, uint32_t second_len)
{
    muxserver_tstate_t *ts        = tunnelGetState(fixture->mux);
    muxserver_lstate_t *parent_ls = lineGetState(fixture->parent_l, fixture->mux);
    muxserver_lstate_t *child_ls  = lineGetState(fixture->child_l, fixture->mux);

    child_ls->paused = true;
    twfRequire(
        muxserverQueueChildPayload(
            fixture->mux, fixture->parent_l, ts, parent_ls, child_ls, makeMuxserverQueuedPayload(fixture, first_len)),
        "queueing the first paused server child payload failed");
    twfRequire(
        muxserverQueueChildPayload(
            fixture->mux, fixture->parent_l, ts, parent_ls, child_ls, makeMuxserverQueuedPayload(fixture, second_len)),
        "queueing the second paused server child payload failed");
}

static void queuePausedServerPayload(muxserver_fixture_t *fixture, line_t *parent_l, line_t *child_l, uint32_t length)
{
    muxserver_tstate_t *ts        = tunnelGetState(fixture->mux);
    muxserver_lstate_t *parent_ls = lineGetState(parent_l, fixture->mux);
    muxserver_lstate_t *child_ls  = lineGetState(child_l, fixture->mux);
    child_ls->paused              = true;
    twfRequire(muxserverQueueChildPayload(
                   fixture->mux, parent_l, ts, parent_ls, child_ls, makeMuxserverQueuedPayload(fixture, length)),
               "queueing a paused server child payload failed");
}

static line_t *createPausedServerChild(muxserver_fixture_t *fixture, muxserver_lstate_t *parent_ls, mux_cid_t cid)
{
    line_t             *child_l  = twfLinePoolCreateLine(&fixture->lines);
    muxserver_lstate_t *child_ls = lineGetState(child_l, fixture->mux);

    muxserverLinestateInitialize(child_ls, child_l, true, cid);
    child_ls->paused = true;
    muxserverJoinConnection(parent_ls, child_ls);
    return child_l;
}

static line_t *createServerParent(muxserver_fixture_t *fixture)
{
    line_t *parent_l = twfLinePoolCreateLine(&fixture->lines);
    muxserverLinestateInitialize(lineGetState(parent_l, fixture->mux), parent_l, false, 0);
    return parent_l;
}

static void destroySurvivingServerChild(muxserver_fixture_t *fixture, line_t *child_l)
{
    muxserver_lstate_t *child_ls  = lineGetState(child_l, fixture->mux);
    muxserver_lstate_t *parent_ls = child_ls->parent;
    muxserverLeaveConnection(child_ls);
    discard muxserverReleaseParentInputForChildClose(fixture->mux, fixture->parent_l, parent_ls, child_ls);
    muxserverLinestateDestroy(child_ls);
    lineDestroy(child_l);
}

/*
 * Mirror the client-side skewed-queue regression with real owned child lines.
 * The small trigger sits at the list head, while the actual pressure source is
 * an older child with a much larger queue.
 */
static void caseParentBufferLimitClosesActualLargestQueue(void)
{
    twfSetCase("muxserver parent budget closes the actual largest queued child");

    enum
    {
        kIdleChildren = 3,
        kLargeQueue   = 48u * 1024u,
        kTriggerQueue = 20u * 1024u,
        kParentLimit  = 64u * 1024u
    };

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture);

    muxserver_tstate_t *ts         = tunnelGetState(fixture.mux);
    muxserver_lstate_t *parent_ls  = lineGetState(fixture.parent_l, fixture.mux);
    muxserver_lstate_t *trigger_ls = lineGetState(fixture.child_l, fixture.mux);

    ts->parent_buffer_limit = kParentLimit;
    trigger_ls->paused      = true;

    line_t *large_l = createPausedServerChild(&fixture, parent_ls, kTestChildCid + 1U);
    line_t *idle[kIdleChildren];
    for (uint32_t i = 0; i < (uint32_t) kIdleChildren; ++i)
    {
        idle[i] = createPausedServerChild(&fixture, parent_ls, kTestChildCid + 2U + i);
    }

    muxserverLeaveConnection(trigger_ls);
    muxserverJoinConnection(parent_ls, trigger_ls);

    muxserver_lstate_t *large_ls = lineGetState(large_l, fixture.mux);
    lineLock(large_l);

    twfRequire(
        muxserverQueueChildPayload(
            fixture.mux, fixture.parent_l, ts, parent_ls, large_ls, makeMuxserverQueuedPayload(&fixture, kLargeQueue)),
        "queueing the large stalled child tore down the parent");
    twfRequire(muxserverQueueChildPayload(fixture.mux,
                                          fixture.parent_l,
                                          ts,
                                          parent_ls,
                                          trigger_ls,
                                          makeMuxserverQueuedPayload(&fixture, kTriggerQueue)),
               "shedding the largest owned child tore down the parent");

    twfRequire(lineIsAlive(fixture.parent_l), "the borrowed parent was closed under child queue pressure");
    twfRequire(! lineIsAlive(large_l), "the largest owned child was not destroyed");
    twfRequireLineStateZeroed(large_l, fixture.mux, "the largest owned child's state was not destroyed");
    twfRequire(lineIsAlive(fixture.child_l), "the smaller trigger child was destroyed instead of the largest queue");
    twfRequire(trigger_ls->parent == parent_ls, "the smaller trigger child was unlinked");
    twfRequireEqualU32(parent_ls->children_count, 1U + kIdleChildren, "the shed child was not unlinked exactly once");
    twfRequireEqualU32((uint32_t) parent_ls->pending_child_data_len,
                       kTriggerQueue,
                       "closing the largest owned child did not release its queue");
    twfRequireEqualText(
        fixture.trace.seq, "pF", "queue pressure must emit one Close and child Finish without pausing the parent");

    lineUnlock(large_l);
    for (uint32_t i = 0; i < (uint32_t) kIdleChildren; ++i)
    {
        destroySurvivingServerChild(&fixture, idle[i]);
    }
    destroySurvivingServerChild(&fixture, fixture.child_l);
    fixtureTeardown(&fixture);
}

static void caseParentBufferLimitCanBeDisabled(void)
{
    twfSetCase("muxserver parent-buffer-limit zero disables aggregate shedding");

    enum
    {
        kQueuedBytes = 32u * 1024u
    };

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture);

    muxserver_tstate_t *ts        = tunnelGetState(fixture.mux);
    muxserver_lstate_t *parent_ls = lineGetState(fixture.parent_l, fixture.mux);
    muxserver_lstate_t *child_ls  = lineGetState(fixture.child_l, fixture.mux);

    ts->parent_buffer_limit = kMuxParentBufferLimitUnlimited;
    child_ls->paused        = true;

    twfRequire(
        muxserverQueueChildPayload(
            fixture.mux, fixture.parent_l, ts, parent_ls, child_ls, makeMuxserverQueuedPayload(&fixture, kQueuedBytes)),
        "an unlimited server parent budget tore down the parent");
    twfRequire(lineIsAlive(fixture.child_l), "an unlimited server parent budget destroyed its child");
    twfRequire(child_ls->parent == parent_ls, "an unlimited server parent budget unlinked its child");
    twfRequireEqualU32((uint32_t) parent_ls->pending_child_data_len,
                       kQueuedBytes,
                       "the unlimited server budget lost queued-byte accounting");
    twfRequireEqualText(fixture.trace.seq, "", "an unlimited server budget emitted flow or close callbacks");

    destroySurvivingServerChild(&fixture, fixture.child_l);
    fixtureTeardown(&fixture);
}

static void casePeerCloseWaitsForOwnedChildResume(void)
{
    twfSetCase("MuxServer peer Close waits for its paused owned child queue");

    enum
    {
        kFirst  = 13,
        kSecond = 17
    };
    muxserver_fixture_t fixture;
    fixtureSetup(&fixture);
    queueTwoPausedServerPayloads(&fixture, kFirst, kSecond);

    muxserver_tstate_t *ts        = tunnelGetState(fixture.mux);
    muxserver_lstate_t *parent_ls = lineGetState(fixture.parent_l, fixture.mux);
    muxserver_lstate_t *child_ls  = lineGetState(fixture.child_l, fixture.mux);

    twfRequire(muxserverBeginPeerCloseDrain(fixture.mux, fixture.parent_l, ts, parent_ls, child_ls),
               "peer Close unexpectedly killed the borrowed parent");
    twfRequireEqualU32(fixture.trace.next_payload, 0, "peer Close forced Payload through child Pause");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "peer Close finished the owned child before its queue drained");
    twfRequire(child_ls->close_state == kMuxServerChildClosePeerDraining,
               "peer Close did not publish server drain state");
    twfRequire(child_ls->parent == parent_ls, "blocked peer-close child was removed from attached routing");

    lineLock(fixture.child_l);
    muxserverTunnelDownStreamResume(fixture.mux, fixture.child_l);
    twfRequire(! lineIsAlive(fixture.child_l), "peer-close completion left the owned child alive");
    twfRequireEqualText(fixture.trace.seq, "UPPF", "server peer-close callback order is wrong");
    twfRequireEqualU32(fixture.trace.next_payload_bytes, kFirst + kSecond, "server peer-close drain lost bytes");
    twfRequireEqualU32(parent_ls->children_count, 0, "server peer-close completion left a child attached");
    twfRequireEqualU32(
        (uint32_t) parent_ls->pending_child_data_len, 0, "server peer-close completion retained parent accounting");
    twfRequireOwnedLineReclaimed(fixture.child_l, "MuxServer peer-close completion");

    fixtureTeardown(&fixture);
}

static void caseParentLossRegistersAndDrainsOwnedChild(void)
{
    twfSetCase("MuxServer parent loss registers a paused owned child until Resume");

    enum
    {
        kFirst  = 19,
        kSecond = 23
    };
    muxserver_fixture_t fixture;
    fixtureSetup(&fixture);
    uint8_t capture[kFirst + kSecond];
    fixture.trace.capture          = capture;
    fixture.trace.capture_capacity = sizeof(capture);
    queueTwoPausedServerPayloads(&fixture, kFirst, kSecond);

    muxserver_tstate_t *ts       = tunnelGetState(fixture.mux);
    muxserver_lstate_t *child_ls = lineGetState(fixture.child_l, fixture.mux);
    muxserverTunnelUpStreamFinish(fixture.mux, fixture.parent_l);

    muxserver_detached_registry_t *registry = &ts->detached_registries[0];
    twfRequire(lineIsAlive(fixture.parent_l), "MuxServer destroyed its borrowed parent");
    twfRequireLineStateZeroed(fixture.parent_l, fixture.mux, "MuxServer retained dead parent state");
    twfRequire(lineIsAlive(fixture.child_l), "MuxServer destroyed a blocked detached owned child");
    twfRequire(child_ls->is_child, "server detachment changed the immutable child role");
    twfRequire(child_ls->parent == NULL, "detached owned child retained the dead parent pointer");
    twfRequire(child_ls->detached_registered, "detached owned child was not published in the registry");
    twfRequire(registry->head == child_ls, "detached registry head does not own the child");
    twfRequireEqualU32(registry->count, 1, "detached owned child count is wrong");
    twfRequireEqualU32((uint32_t) registry->queued_bytes, kFirst + kSecond, "detached owned byte accounting is wrong");
    twfRequireEqualU32(fixture.trace.next_payload, 0, "parent loss forced Payload through child Pause");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "parent loss finished a blocked owned child early");

    lineLock(fixture.child_l);
    muxserverTunnelDownStreamResume(fixture.mux, fixture.child_l);

    twfRequire(! lineIsAlive(fixture.child_l), "detached Resume left the owned child alive");
    twfRequireEqualText(fixture.trace.seq, "UPPF", "detached owned drain callback order is wrong");
    twfRequireEqualU32(registry->count, 0, "detached registry count survived completion");
    twfRequireEqualU32((uint32_t) registry->queued_bytes, 0, "detached registry bytes survived completion");
    twfRequire(registry->head == NULL, "detached registry head survived completion");
    for (uint32_t i = 0; i < kFirst; ++i)
    {
        twfRequire(capture[i] == (uint8_t) kFirst, "detached drain reordered the first buffer");
    }
    for (uint32_t i = kFirst; i < kFirst + kSecond; ++i)
    {
        twfRequire(capture[i] == (uint8_t) kSecond, "detached drain reordered the second buffer");
    }
    twfRequireOwnedLineReclaimed(fixture.child_l, "MuxServer detached Resume");

    fixtureTeardown(&fixture);
}

static void caseDetachedLocalFinishAbortsResidualQueue(void)
{
    twfSetCase("MuxServer detached downstream Finish aborts residual data without reflection");

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture);
    queueTwoPausedServerPayloads(&fixture, 11, 29);
    muxserverTunnelUpStreamFinish(fixture.mux, fixture.parent_l);

    muxserver_tstate_t *ts = tunnelGetState(fixture.mux);
    twfRunOwnerFinish(
        fixture.mux, fixture.child_l, muxserverTunnelDownStreamFinish, "detached muxserverTunnelDownStreamFinish");

    twfRequireEqualU32(fixture.trace.next_payload, 0, "detached local Finish forwarded residual Payload");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "detached local Finish reflected Finish toward its sender");
    twfRequireEqualU32(ts->detached_registries[0].count, 0, "detached local Finish retained registry membership");
    twfRequireEqualU32(
        (uint32_t) ts->detached_registries[0].queued_bytes, 0, "detached local Finish retained queued-byte accounting");
    twfRequireOwnedLineReclaimed(fixture.child_l, "detached muxserverTunnelDownStreamFinish");

    fixtureTeardown(&fixture);
}

static void caseWorkerStopDiscardsDetachedQueue(void)
{
    twfSetCase("MuxServer worker stop discards detached data without Payload");

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture);
    queueTwoPausedServerPayloads(&fixture, 7, 31);
    muxserverTunnelUpStreamFinish(fixture.mux, fixture.parent_l);

    muxserver_lstate_t *child_ls = lineGetState(fixture.child_l, fixture.mux);
    child_ls->paused             = false; // writable still must not create new work after shutdown commit
    lineLock(fixture.child_l);
    muxserverTunnelOnWorkerStop(fixture.mux, 0, wwLifecycleProcessShutdown());

    muxserver_tstate_t *ts = tunnelGetState(fixture.mux);
    twfRequire(! lineIsAlive(fixture.child_l), "worker stop left a detached owned child alive");
    twfRequireEqualU32(fixture.trace.next_payload, 0, "worker stop forwarded detached Payload");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "worker stop did not finish the child exactly once");
    twfRequire(ts->detached_registries[0].head == NULL, "worker stop retained the detached registry head");
    twfRequireEqualU32(ts->detached_registries[0].count, 0, "worker stop retained detached children");
    twfRequireEqualU32((uint32_t) ts->detached_registries[0].queued_bytes, 0, "worker stop retained detached bytes");
    twfRequireOwnedLineReclaimed(fixture.child_l, "MuxServer worker stop");

    muxserverTunnelOnWorkerStop(fixture.mux, 0, wwLifecycleProcessShutdown());
    fixtureTeardown(&fixture);
}

static void caseDetachedChildLimitAbortsOnlyNewBlockedChild(void)
{
    twfSetCase("MuxServer detached child limit aborts a newly blocked child");

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture);
    queueTwoPausedServerPayloads(&fixture, 5, 9);
    muxserver_tstate_t *ts   = tunnelGetState(fixture.mux);
    ts->detached_child_limit = 1;

    lineLock(fixture.child_l);
    muxserverTunnelUpStreamFinish(fixture.mux, fixture.parent_l);

    twfRequire(! lineIsAlive(fixture.child_l), "detached child limit retained the rejected child");
    twfRequireEqualU32(fixture.trace.next_payload, 0, "detached child limit force-forwarded Payload");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "detached child limit did not finish the rejected child");
    twfRequire(ts->detached_registries[0].head == NULL, "detached child limit corrupted the registry head");
    twfRequireEqualU32(ts->detached_registries[0].count, 0, "detached child limit retained registry membership");
    twfRequireEqualU32((uint32_t) ts->detached_registries[0].queued_bytes, 0, "detached child limit retained bytes");
    twfRequireOwnedLineReclaimed(fixture.child_l, "MuxServer detached child limit");

    fixtureTeardown(&fixture);
}

static void requireDetachedRegistryLinks(muxserver_detached_registry_t *registry, uint32_t expected_count,
                                         size_t expected_bytes, const char *message)
{
    uint32_t            count = 0;
    size_t              bytes = 0;
    muxserver_lstate_t *prev  = NULL;
    for (muxserver_lstate_t *ls = registry->head; ls != NULL; ls = ls->detached_next)
    {
        twfRequire(ls->detached_registered, message);
        twfRequire(ls->detached_prev == prev, message);
        twfRequire(ls->parent == NULL && ls->close_state == kMuxServerChildCloseParentGoneDraining, message);
        bytes += bufferqueueGetBufLen(&ls->pending_child_data);
        prev = ls;
        ++count;
    }
    twfRequireEqualU32(count, expected_count, message);
    twfRequireEqualU32(registry->count, expected_count, message);
    twfRequireEqualU32((uint32_t) bytes, (uint32_t) expected_bytes, message);
    twfRequireEqualU32((uint32_t) registry->queued_bytes, (uint32_t) expected_bytes, message);
}

static void casePopulatedDetachedRegistrySupportsEveryRemovalPosition(void)
{
    twfSetCase("MuxServer populated detached registry preserves links and exact accounting");

    static const uint32_t kQueueBytes[] = {5, 7, 11, 13};

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture);
    muxserver_lstate_t *parent_ls = lineGetState(fixture.parent_l, fixture.mux);
    line_t             *children[ARRAY_SIZE(kQueueBytes)];
    children[0] = fixture.child_l;
    for (uint32_t i = 1; i < ARRAY_SIZE(children); ++i)
    {
        children[i] = createPausedServerChild(&fixture, parent_ls, kTestChildCid + i);
    }
    for (uint32_t i = 0; i < ARRAY_SIZE(children); ++i)
    {
        queuePausedServerPayload(&fixture, fixture.parent_l, children[i], kQueueBytes[i]);
    }

    muxserverTunnelUpStreamFinish(fixture.mux, fixture.parent_l);

    muxserver_tstate_t            *ts       = tunnelGetState(fixture.mux);
    muxserver_detached_registry_t *registry = &ts->detached_registries[0];
    size_t                         total    = 0;
    for (uint32_t i = 0; i < ARRAY_SIZE(kQueueBytes); ++i)
    {
        total += kQueueBytes[i];
    }
    requireDetachedRegistryLinks(registry, ARRAY_SIZE(children), total, "initial populated registry is inconsistent");

    muxserver_lstate_t *head_ls    = registry->head;
    line_t             *head_l     = head_ls->l;
    size_t              head_bytes = bufferqueueGetBufLen(&head_ls->pending_child_data);
    muxserver_lstate_t *head_next  = head_ls->detached_next;
    lineLock(head_l);
    muxserverTunnelDownStreamResume(fixture.mux, head_l);
    twfRequire(! lineIsAlive(head_l), "draining the detached registry head left it alive");
    twfRequireLineStateZeroed(head_l, fixture.mux, "draining the detached registry head retained state");
    total -= head_bytes;
    requireDetachedRegistryLinks(registry, 3, total, "head removal corrupted the detached registry");
    twfRequire(registry->head == head_next && head_next->detached_prev == NULL,
               "head removal did not publish the exact next registry entry");
    twfRequireEqualU32(fixture.trace.next_payload, 1, "head drain did not forward exactly one payload");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "head drain did not send exactly one Finish");
    twfRequireOwnedLineReclaimed(head_l, "MuxServer detached registry head drain");

    muxserver_lstate_t *middle_ls = registry->head->detached_next;
    twfRequire(middle_ls != NULL && middle_ls->detached_prev != NULL && middle_ls->detached_next != NULL,
               "the populated registry has no true middle entry after head removal");
    line_t             *middle_l     = middle_ls->l;
    size_t              middle_bytes = bufferqueueGetBufLen(&middle_ls->pending_child_data);
    muxserver_lstate_t *middle_prev  = middle_ls->detached_prev;
    muxserver_lstate_t *middle_next  = middle_ls->detached_next;
    lineLock(middle_l);
    muxserverTunnelDownStreamFinish(fixture.mux, middle_l);
    twfRequire(! lineIsAlive(middle_l), "downstream Finish left the detached middle child alive");
    twfRequireLineStateZeroed(middle_l, fixture.mux, "downstream Finish retained detached middle state");
    total -= middle_bytes;
    requireDetachedRegistryLinks(registry, 2, total, "middle removal corrupted the detached registry");
    twfRequire(middle_prev->detached_next == middle_next && middle_next->detached_prev == middle_prev,
               "middle removal did not splice both neighboring links");
    twfRequireEqualU32(fixture.trace.next_payload, 1, "middle removal forwarded residual Payload");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "middle removal reflected Finish toward its sender");
    twfRequireOwnedLineReclaimed(middle_l, "MuxServer detached registry middle Finish");

    line_t *remaining[2] = {registry->head->l, registry->head->detached_next->l};
    lineLock(remaining[0]);
    lineLock(remaining[1]);
    muxserverTunnelOnWorkerStop(fixture.mux, 0, wwLifecycleProcessShutdown());
    twfRequire(registry->head == NULL, "worker stop retained the final detached registry head");
    twfRequireEqualU32(registry->count, 0, "worker stop retained populated-registry children");
    twfRequireEqualU32((uint32_t) registry->queued_bytes, 0, "worker stop retained populated-registry bytes");
    twfRequireEqualU32(fixture.trace.next_payload, 1, "worker stop forwarded queued detached Payload");
    twfRequireEqualU32(fixture.trace.next_finish, 3, "worker stop did not finish both remaining children once");
    for (uint32_t i = 0; i < ARRAY_SIZE(remaining); ++i)
    {
        twfRequire(! lineIsAlive(remaining[i]), "worker stop left a remaining detached child alive");
        twfRequireLineStateZeroed(remaining[i], fixture.mux, "worker stop retained remaining detached child state");
        twfRequireOwnedLineReclaimed(remaining[i], "MuxServer populated registry worker stop");
    }

    fixture.child_l = NULL;
    fixtureTeardown(&fixture);
}

static void runMuxserverDetachedByteLimitCase(bool unlimited)
{
    twfSetCase(unlimited ? "MuxServer detached byte limit zero retains both owned children"
                         : "MuxServer detached byte limit aborts only the new owned child");

    enum
    {
        kOlderBytes = 23,
        kNewBytes   = 31
    };
    muxserver_fixture_t fixture;
    fixtureSetup(&fixture);

    muxserver_tstate_t *ts = tunnelGetState(fixture.mux);
    queuePausedServerPayload(&fixture, fixture.parent_l, fixture.child_l, kOlderBytes);
    muxserverTunnelUpStreamFinish(fixture.mux, fixture.parent_l);
    muxserver_detached_registry_t *registry = &ts->detached_registries[0];
    requireDetachedRegistryLinks(registry, 1, kOlderBytes, "older detached server child was not retained");

    line_t             *new_parent    = createServerParent(&fixture);
    muxserver_lstate_t *new_parent_ls = lineGetState(new_parent, fixture.mux);
    line_t             *new_child     = createPausedServerChild(&fixture, new_parent_ls, kTestChildCid + 1U);
    queuePausedServerPayload(&fixture, new_parent, new_child, kNewBytes);

    ts->detached_child_limit  = kMuxDetachedLimitUnlimited;
    ts->detached_buffer_limit = unlimited ? kMuxDetachedLimitUnlimited : kOlderBytes + kNewBytes;
    lineLock(new_child);
    muxserverTunnelUpStreamFinish(fixture.mux, new_parent);

    if (unlimited)
    {
        twfRequire(lineIsAlive(new_child), "zero server detached byte limit rejected the new owned child");
        requireDetachedRegistryLinks(
            registry, 2, kOlderBytes + kNewBytes, "zero server detached byte limit lost registry accounting");
        muxserverTunnelDownStreamResume(fixture.mux, new_child);
        twfRequire(! lineIsAlive(new_child), "unlimited detached server child did not drain normally");
        twfRequireLineStateZeroed(new_child, fixture.mux, "unlimited detached server child retained state");
    }
    else
    {
        twfRequire(! lineIsAlive(new_child), "server detached byte limit retained the rejected new child");
        twfRequireLineStateZeroed(new_child, fixture.mux, "server detached byte limit retained rejected child state");
        requireDetachedRegistryLinks(
            registry, 1, kOlderBytes, "server detached byte limit changed the older detached child");
    }
    twfRequireOwnedLineReclaimed(new_child, "MuxServer detached byte-limit new child");

    twfRequire(lineIsAlive(new_parent), "MuxServer destroyed the borrowed second parent");
    twfRequireLineStateZeroed(new_parent, fixture.mux, "MuxServer retained second parent state after loss");
    lineDestroy(new_parent);

    lineLock(fixture.child_l);
    muxserverTunnelDownStreamResume(fixture.mux, fixture.child_l);
    twfRequire(! lineIsAlive(fixture.child_l), "older detached server child did not drain after limit handling");
    twfRequireLineStateZeroed(fixture.child_l, fixture.mux, "older detached server child retained state");
    twfRequireOwnedLineReclaimed(fixture.child_l, "MuxServer detached byte-limit older child");
    fixture.child_l = NULL;
    twfRequire(registry->head == NULL, "server detached byte-limit drain retained registry head");
    twfRequireEqualU32(registry->count, 0, "server detached byte-limit drain retained registry count");
    twfRequireEqualU32(
        (uint32_t) registry->queued_bytes, 0, "server detached byte-limit drain retained registry bytes");

    fixtureTeardown(&fixture);
}

static tunnel_t *g_reentrant_pause_mux = NULL;

static void pauseServerChildAfterFirstPayload(tunnel_t *next, line_t *child_l, sbuf_t *buf)
{
    twfNextPayload(next, child_l, buf);
    if (g_reentrant_pause_mux != NULL)
    {
        tunnel_t *mux         = g_reentrant_pause_mux;
        g_reentrant_pause_mux = NULL;
        muxserverTunnelDownStreamPause(mux, child_l);
    }
}

static void caseDetachedDrainStopsOnReentrantPause(void)
{
    twfSetCase("MuxServer detached drain stops on a re-entrant child Pause");

    enum
    {
        kFirst  = 17,
        kSecond = 37
    };
    muxserver_fixture_t fixture;
    fixtureSetup(&fixture);
    queueTwoPausedServerPayloads(&fixture, kFirst, kSecond);

    muxserver_lstate_t *child_ls = lineGetState(fixture.child_l, fixture.mux);
    child_ls->paused             = false;
    fixture.next->fnPayloadU     = pauseServerChildAfterFirstPayload;
    g_reentrant_pause_mux        = fixture.mux;

    muxserverTunnelUpStreamFinish(fixture.mux, fixture.parent_l);

    muxserver_tstate_t *ts = tunnelGetState(fixture.mux);
    twfRequireEqualU32(fixture.trace.next_payload, 1, "re-entrant Pause did not stop after the first Payload");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "re-entrant Pause allowed early Finish");
    twfRequireEqualU32((uint32_t) ts->detached_registries[0].queued_bytes,
                       kSecond,
                       "re-entrant Pause corrupted residual detached bytes");
    twfRequire(child_ls->paused, "re-entrant Pause was not retained on the detached child");

    fixture.next->fnPayloadU = twfNextPayload;
    lineLock(fixture.child_l);
    muxserverTunnelDownStreamResume(fixture.mux, fixture.child_l);

    twfRequire(! lineIsAlive(fixture.child_l), "second Resume left the detached owned child alive");
    twfRequireEqualText(fixture.trace.seq, "PUPF", "re-entrant detached drain callback order is wrong");
    twfRequireEqualU32(fixture.trace.next_payload_bytes, kFirst + kSecond, "re-entrant detached drain lost bytes");
    twfRequireOwnedLineReclaimed(fixture.child_l, "MuxServer re-entrant detached drain");

    fixtureTeardown(&fixture);
}

int main(void)
{
    caseInternalOwnerFinishKillsChildOnly();
    caseParentFinishKillsOwnedChildren();
    caseNestedDestroyIsNotRepeated();
    caseParentBufferLimitClosesActualLargestQueue();
    caseParentBufferLimitCanBeDisabled();
    casePeerCloseWaitsForOwnedChildResume();
    caseParentLossRegistersAndDrainsOwnedChild();
    caseDetachedLocalFinishAbortsResidualQueue();
    caseWorkerStopDiscardsDetachedQueue();
    caseDetachedChildLimitAbortsOnlyNewBlockedChild();
    casePopulatedDetachedRegistrySupportsEveryRemovalPosition();
    runMuxserverDetachedByteLimitCase(false);
    runMuxserverDetachedByteLimitCase(true);
    caseDetachedDrainStopsOnReentrantPause();

    printf("owned_line_finish_muxserver_test: all cases passed\n");
    return 0;
}
