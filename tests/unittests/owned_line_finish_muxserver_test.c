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
    fixture->mux  = tunnelCreate(NULL, sizeof(muxserver_tstate_t), sizeof(muxserver_lstate_t));
    twfRequire(fixture->mux != NULL, "failed to create the MuxServer tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);

    tunnelBind(fixture->prev, fixture->mux);
    tunnelBind(fixture->mux, fixture->next);

    muxserver_tstate_t *ts           = tunnelGetState(fixture->mux);
    ts->child_buffer_limit           = kMuxDefaultChildBufferLimit;
    ts->child_buffer_pause_tolerance = kMuxDefaultChildBufferPauseTolerance;
    ts->parent_buffer_limit          = kMuxDefaultParentBufferLimit;

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
    return buf;
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

static void destroySurvivingServerChild(muxserver_fixture_t *fixture, line_t *child_l)
{
    muxserver_lstate_t *child_ls = lineGetState(child_l, fixture->mux);
    muxserverLeaveConnection(child_ls);
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

    twfRequire(muxserverQueueChildPayload(fixture.mux,
                                          fixture.parent_l,
                                          ts,
                                          parent_ls,
                                          large_ls,
                                          makeMuxserverQueuedPayload(&fixture, kLargeQueue)),
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
    twfRequireEqualText(fixture.trace.seq,
                        "pF",
                        "queue pressure must emit one Close and child Finish without pausing the parent");

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

    twfRequire(muxserverQueueChildPayload(fixture.mux,
                                          fixture.parent_l,
                                          ts,
                                          parent_ls,
                                          child_ls,
                                          makeMuxserverQueuedPayload(&fixture, kQueuedBytes)),
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

int main(void)
{
    caseInternalOwnerFinishKillsChildOnly();
    caseParentFinishKillsOwnedChildren();
    caseNestedDestroyIsNotRepeated();
    caseParentBufferLimitClosesActualLargestQueue();
    caseParentBufferLimitCanBeDisabled();

    printf("owned_line_finish_muxserver_test: all cases passed\n");
    return 0;
}
