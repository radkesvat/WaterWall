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

// ---------------------------------------------------------------------------
// The parent budget sheds queued children instead of pausing the parent
// ---------------------------------------------------------------------------

/*
 * `parent-buffer-limit` is the only bound that covers a parent whose children each stay well
 * under `child-buffer-limit`. Before it existed those queues paused the shared parent transport
 * instead, and a child that never drained held that pause shut for every other stream.
 */
static void caseParentBufferLimitShedsQueuedChildren(void)
{
    twfSetCase("the parent buffer limit sheds queued children instead of pausing the parent");

    enum
    {
        kShedExtraChildren = 3,
        kShedChildren      = kShedExtraChildren + 1,
        kShedPayload       = 8u * 1024u,
        kShedParentLimit   = 24u * 1024u
    };

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture);

    muxserver_tstate_t *ts        = tunnelGetState(fixture.mux);
    muxserver_lstate_t *parent_ls = lineGetState(fixture.parent_l, fixture.mux);

    // the per-child limit stays far above anything queued here, so only the parent budget can shed
    ts->child_buffer_limit  = kMuxDefaultChildBufferLimit;
    ts->parent_buffer_limit = kShedParentLimit;

    line_t *children[kShedChildren];
    children[0] = fixture.child_l;
    for (uint32_t i = 1; i < (uint32_t) kShedChildren; ++i)
    {
        children[i]                  = twfLinePoolCreateLine(&fixture.lines);
        muxserver_lstate_t *extra_ls = lineGetState(children[i], fixture.mux);
        muxserverLinestateInitialize(extra_ls, children[i], true, kTestChildCid + i);
        muxserverJoinConnection(parent_ls, extra_ls);
    }
    for (uint32_t i = 0; i < (uint32_t) kShedChildren; ++i)
    {
        muxserver_lstate_t *paused_ls = lineGetState(children[i], fixture.mux);
        paused_ls->paused             = true;
    }
    twfRequireEqualU32(parent_ls->children_count, kShedChildren, "the case must start with every child attached");

    for (uint32_t i = 0; i < (uint32_t) kShedChildren; ++i)
    {
        muxserver_lstate_t *child_ls = lineGetState(children[i], fixture.mux);
        sbuf_t             *buf      = bufferpoolGetLargeBuffer(fixture.env.pool);
        buf                          = sbufReserveSpace(buf, kShedPayload);
        sbufSetLength(buf, kShedPayload);
        twfRequire(muxserverQueueChildPayload(fixture.mux, fixture.parent_l, ts, parent_ls, child_ls, buf),
                   "queueing a child payload tore the parent down");
    }

    twfRequire(lineIsAlive(fixture.parent_l), "the parent line was closed instead of shedding a child");
    twfRequire(parent_ls->pending_child_data_len < (size_t) kShedParentLimit,
               "the parent queue stayed at or above its budget after shedding");
    twfRequire(parent_ls->children_count < (uint32_t) kShedChildren, "no child was shed at the parent budget");

    const uint32_t shed = (uint32_t) kShedChildren - parent_ls->children_count;
    twfRequireEqualU32(fixture.trace.prev_payload, shed, "the peer was not told about every shed child");
    twfRequireEqualU32(fixture.trace.next_finish, shed, "a shed child was never finished toward its own side");

    // the survivors still own line state; the shed ones were destroyed by the shed itself
    for (uint32_t i = 0; i < (uint32_t) kShedChildren; ++i)
    {
        muxserver_lstate_t *child_ls = lineGetState(children[i], fixture.mux);
        if (child_ls->parent != NULL)
        {
            muxserverLeaveConnection(child_ls);
            muxserverLinestateDestroy(child_ls);
            lineDestroy(children[i]);
        }
    }

    fixtureTeardown(&fixture);
}

int main(void)
{
    caseInternalOwnerFinishKillsChildOnly();
    caseParentFinishKillsOwnedChildren();
    caseNestedDestroyIsNotRepeated();
    caseParentBufferLimitShedsQueuedChildren();

    printf("owned_line_finish_muxserver_test: all cases passed\n");
    return 0;
}
