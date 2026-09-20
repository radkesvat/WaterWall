/* Shared behavioral cases, included by the two existing Mux framing fixtures. */
#ifdef MUX_OUTPUT_CLIENT
#define pq_fixture_t         muxclient_fixture_t
#define pq_state_t           muxclient_lstate_t
#define pq_tstate_t          muxclient_tstate_t
#define pqQueue              muxclientQueueChildPayload
#define pqSend               muxclientTunnelUpStreamPayload
#define pqReceive            muxclientTunnelDownStreamPayload
#define pqChildDeliveries(f) ((f)->trace.prev_payload)
#define pqPause              muxclientTunnelDownStreamPause
#define pqResume             muxclientTunnelDownStreamResume
#define pqControl            muxclientSendControlFrame
#define pqLoss               muxclientHandleParentLoss
#define pqFinish             muxclientTunnelUpStreamFinish
#define pqPeerPause          muxclientPauseChildSource
#define pqPeerResume         muxclientResumeChildSource
#define pqCreate             muxclientTunnelCreate
#define pqDestroy            muxclientTunnelDestroy
#define pqSibling            createPausedClientChild
#define pqDestroySibling     destroySurvivingClientChild
#define pqParentSink(f)      ((f)->next)
#define pqSource(f)          ((f)->prev)
#define pqPayloadSlot        fnPayloadU
#define pqPauseSlot          fnPauseD
#define pqResumeSlot         fnResumeD
#define pqCapture            twfNextPayload
#define pqStop               muxclientTunnelOnWorkerStop
#else
#define pq_fixture_t         muxserver_fixture_t
#define pq_state_t           muxserver_lstate_t
#define pq_tstate_t          muxserver_tstate_t
#define pqQueue              muxserverQueueChildPayload
#define pqSend               muxserverTunnelDownStreamPayload
#define pqReceive            muxserverTunnelUpStreamPayload
#define pqChildDeliveries(f) ((f)->trace.next_payload)
#define pqPause              muxserverTunnelUpStreamPause
#define pqResume             muxserverTunnelUpStreamResume
#define pqControl            muxserverSendControlFrame
#define pqLoss               muxserverHandleParentLoss
#define pqFinish             muxserverTunnelDownStreamFinish
#define pqPeerPause          muxserverPauseChildSource
#define pqPeerResume         muxserverResumeChildSource
#define pqCreate             muxserverTunnelCreate
#define pqDestroy            muxserverTunnelDestroy
#define pqSibling            createServerSibling
#define pqDestroySibling     destroyServerSibling
#define pqParentSink(f)      ((f)->prev)
#define pqSource(f)          ((f)->next)
#define pqPayloadSlot        fnPayloadD
#define pqPauseSlot          fnPauseU
#define pqResumeSlot         fnResumeU
#define pqCapture            twfPrevPayload
#define pqStop               muxserverTunnelOnWorkerStop
#endif

/* sbufConcat may grow its first buffer. Its internal destruction is in the
 * same translation unit as sbufDestroy, so --wrap=sbufDestroy cannot observe
 * that call. Track the replacement at the public concat boundary instead. */
sbuf_t *__real_sbufConcat(sbuf_t *root, const sbuf_t *buf);
sbuf_t *__wrap_sbufConcat(sbuf_t *root, const sbuf_t *buf);

sbuf_t *__wrap_sbufConcat(sbuf_t *root, const sbuf_t *buf)
{
    sbuf_t *result = __real_sbufConcat(root, buf);
    if (result != root)
    {
        twfLedgerForget(g_twf_buffers.live, &g_twf_buffers.live_count, root);
        twfLedgerForget(g_twf_buffers.recycled, &g_twf_buffers.recycled_count, root);
        if (! twfLedgerContains(g_twf_buffers.live, g_twf_buffers.live_count, result))
            twfTrackAcquired(result);
    }
    return result;
}

#include "mux_splice_retention_probe.h"

static pq_fixture_t *pqFixture;
static unsigned      pqPauses, pqResumes, pqDeliveries;
static bool          pqTransportPaused;
static unsigned      pqPauseAt, pqNestedAt, pqToggleAt;
static bool          pqReblockOnResume, pqResumeInPause;
static line_t       *pqRemoveOnPause;
static bool          pqCloseSelfOnPause;
static line_t       *pqPeerResumeUnvisited;

static void pqParentPause(pq_fixture_t *f)
{
    pqTransportPaused = true;
    pqPause(f->mux, f->parent_l);
}

static void pqParentResume(pq_fixture_t *f)
{
    pqTransportPaused = false;
    pqResume(f->mux, f->parent_l);
}

static void pqSink(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    twfRequire(! pqTransportPaused, "strict parent received output while paused");
    ++pqDeliveries;
    pqCapture(t, l, buf);
    if (pqDeliveries == pqNestedAt)
        pqSend(pqFixture->mux, pqFixture->child_l, makePatternPayload(pqFixture, 4));
    if (pqDeliveries == pqPauseAt)
        pqParentPause(pqFixture);
    if (pqDeliveries == pqToggleAt)
    {
        pqParentPause(pqFixture);
        pqParentResume(pqFixture);
    }
}

static void pqSourcePause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    ++pqPauses;
    if (pqPeerResumeUnvisited != NULL)
    {
        line_t *target        = pqPeerResumeUnvisited;
        pqPeerResumeUnvisited = NULL;
        pq_state_t *child     = lineGetState(target, pqFixture->mux);
        discard     pqPeerResume(pqFixture->mux, pqFixture->parent_l, child, true, false);
    }
    if (pqCloseSelfOnPause && l == pqFixture->child_l)
    {
        pqFinish(pqFixture->mux, l);
#ifdef MUX_OUTPUT_CLIENT
        lineDestroy(l);
#endif
        return;
    }
    if (pqResumeInPause)
    {
        pqResumeInPause = false;
        pqParentResume(pqFixture);
    }
    if (pqRemoveOnPause)
    {
        line_t *victim  = pqRemoveOnPause;
        pqRemoveOnPause = NULL;
        pqFinish(pqFixture->mux, victim);
#ifdef MUX_OUTPUT_CLIENT
        lineDestroy(victim); // the fake source owns the borrowed client child
#endif
    }
}

static void pqSourceResume(tunnel_t *t, line_t *l)
{
    discard t;
    ++pqResumes;
    if (pqReblockOnResume)
    {
        pqReblockOnResume = false;
        pqParentPause(pqFixture);
        pqSend(pqFixture->mux, l, makePatternPayload(pqFixture, 1));
    }
}

static void pqSetup(pq_fixture_t *f)
{
    fixtureSetup(f, 4096);
    pqFixture = f;
    pqPauses = pqResumes = pqDeliveries = 0;
    pqPauseAt = pqNestedAt = pqToggleAt = 0;
    pqTransportPaused = pqReblockOnResume = pqResumeInPause = false;
    pqRemoveOnPause                                         = NULL;
    pqCloseSelfOnPause                                      = false;
    pqPeerResumeUnvisited                                   = NULL;
    pqParentSink(f)->pqPayloadSlot                          = pqSink;
    pqSource(f)->pqPauseSlot                                = pqSourcePause;
    pqSource(f)->pqResumeSlot                               = pqSourceResume;
}

static mux_parent_output_t *pqOutput(pq_fixture_t *f)
{
    pq_state_t *parent = lineGetState(f->parent_l, f->mux);
    return &parent->parent_state->output;
}

static void caseParentPumpReentrancy(void)
{
    twfSetCase("parent FIFO handles repeated signals, nested output and synchronous Pause+Resume");
    pq_fixture_t f;
    pqSetup(&f);
    tunnel_t *middle = tunnelCreate(NULL, 0, 0);
    twfRequire(middle != NULL, "failed to create intermediate parent consumer");
#ifdef MUX_OUTPUT_CLIENT
    tunnelBind(f.mux, middle);
    tunnelBind(middle, f.next);
#else
    tunnelBind(f.prev, middle);
    tunnelBind(middle, f.mux);
#endif
    pqPauseAt = 1;
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 2));
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 3));
    pq_state_t *parent = lineGetState(f.parent_l, f.mux);
    twfRequire(pqControl(f.mux, f.parent_l, parent, f.child_l, kTestChildCid, kMuxFlagFlowPause),
               "queued FlowPause failed");
    twfRequire(pqControl(f.mux, f.parent_l, parent, f.child_l, kTestChildCid, kMuxFlagFlowResume),
               "queued FlowResume failed");
    pqParentPause(&f);
    twfRequire(pqPauses == 0 && pqResumes == 0 && pqDeliveries == 1, "short stall walked child producers");
    const size_t charge = pqOutput(&f)->charge;
    pqPauseAt           = 2;
    pqParentResume(&f);
    twfRequire(pqDeliveries == 2 && pqOutput(&f)->charge < charge && pqOutput(&f)->charge > 0,
               "Pause during drain lost residual accounting");
    pqNestedAt = 3;
    pqToggleAt = 3;
    pqParentResume(&f);
    pqParentResume(&f);
    twfRequire(pqDeliveries == 6 && pqOutput(&f)->charge == 0 && pqPauses == 0 && pqResumes == 0,
               "nested output was stranded, duplicated, or caused unnecessary fanout");
    frame_view_t frames[8];
    unsigned     n = parseFrames(f.capture, f.trace.capture_len, frames, 8);
#ifdef MUX_OUTPUT_CLIENT
    twfRequire(frames[0].flags == kMuxFlagOpen, "first Data lost Open");
    unsigned start = 1;
#else
    unsigned start = 0;
#endif
    twfRequire(n == start + 6 && frames[start].length == 1 && frames[start + 1].length == 2 &&
                   frames[start + 2].length == 3 && frames[start + 3].flags == kMuxFlagFlowPause &&
                   frames[start + 4].flags == kMuxFlagFlowResume && frames[start + 5].length == 4,
               "nested Data overtook previously submitted output");
    tunnelBind(f.prev, f.mux);
    tunnelBind(f.mux, f.next);
    tunnelDestroy(middle);
    fixtureTeardown(&f);
}

static void pqEarlyResume(tunnel_t *t, line_t *l)
{
    twfRequire(pqOutput(pqFixture)->charge > 0, "producer release waited for an empty FIFO");
    pqSourceResume(t, l);
}

static void caseParentEarlyRelease(void)
{
    twfSetCase("writable parent releases producers with retained output");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts                   = tunnelGetState(f.mux);
    const size_t charge               = pooledBufferCharge(f.env.pool, false);
    ts->parent_write_pause_threshold  = (uint32_t) (2 * charge);
    ts->parent_write_resume_threshold = (uint32_t) charge;
    ts->parent_write_limit            = (uint32_t) (4 * charge);
    pqSource(&f)->pqResumeSlot        = pqEarlyResume;
    pqParentPause(&f);
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 2));
    pqParentResume(&f);
    twfRequire(pqResumes == 1 && pqOutput(&f)->charge == 0, "early release failed to drain");
    fixtureTeardown(&f);
}

static void caseParentResumeBoundary(unsigned mode)
{
    twfSetCase("resume boundary uses post-delivery transport state and preserves hysteresis");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t   *ts                 = tunnelGetState(f.mux);
    const uint32_t cost               = (uint32_t) pooledBufferCharge(f.env.pool, false);
    ts->parent_write_pause_threshold  = 3 * cost;
    ts->parent_write_resume_threshold = cost + (mode == 2 ? 1 : 0);
    ts->parent_write_limit            = 6 * cost;
    pqParentPause(&f);
    for (unsigned i = 0; i < 3; ++i)
        pqSend(f.mux, f.child_l, makePatternPayload(&f, i + 1));
    pqPauseAt = 1;
    pqParentResume(&f);
    twfRequire(pqOutput(&f)->charge == 2 * cost && pqResumes == 0, "released above resume threshold");
    pqPauseAt = 2;
    pqParentResume(&f);
    twfRequire(pqOutput(&f)->charge == cost && pqResumes == 0, "released before observing transport Pause");
    pqSource(&f)->pqResumeSlot = pqEarlyResume;
    pqPauseAt                  = 3;
    pqParentResume(&f);
    twfRequire(pqResumes == 1 && ! pqOutput(&f)->sources_throttled, "writable low queue did not release");
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 4));
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 5));
    twfRequire(pqPauses == 1 && ! pqOutput(&f)->sources_throttled, "hysteresis reclosed gate below pause");
    pqPauseAt = 0;
    pqParentResume(&f);
    fixtureTeardown(&f);
}

static void pqFifoResume(tunnel_t *t, line_t *l)
{
    pqEarlyResume(t, l);
    pqSend(pqFixture->mux, l, makePatternPayload(pqFixture, 4));
}

static void caseParentResumeFIFO(void)
{
    twfSetCase("synchronous resumed payload follows retained Data and controls");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t   *ts                 = tunnelGetState(f.mux);
    const uint32_t cost               = (uint32_t) pooledBufferCharge(f.env.pool, false);
    ts->parent_write_pause_threshold  = 2 * cost;
    ts->parent_write_resume_threshold = cost;
    ts->parent_write_limit            = 8 * cost;
    pqParentPause(&f);
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 2));
    pq_state_t *parent = lineGetState(f.parent_l, f.mux);
    twfRequire(pqControl(f.mux, f.parent_l, parent, f.child_l, kTestChildCid, kMuxFlagFlowPause),
               "control admission failed");
    pqSource(&f)->pqResumeSlot = pqFifoResume;
    pqParentResume(&f);
    frame_view_t frames[5];
    unsigned     n = parseFrames(f.capture, f.trace.capture_len, frames, 5);
#ifdef MUX_OUTPUT_CLIENT
    const unsigned first = 1;
#else
    const unsigned first = 0;
#endif
    twfRequire(n == first + 4 && frames[first].length == 1 && frames[first + 1].length == 2 &&
                   frames[first + 2].flags == kMuxFlagFlowPause && frames[first + 3].length == 4,
               "resumed source overtook old output");
    fixtureTeardown(&f);
}

static unsigned pqFairSeen[2000];
static bool     pqFairRefill;
static void     pqFairResume(tunnel_t *t, line_t *l)
{
    discard     t;
    pq_state_t *child = lineGetState(l, pqFixture->mux);
    twfRequire(child->connection_id >= 100 && child->connection_id < 2100, "unexpected fairness child");
    pqFairSeen[child->connection_id - 100]++;
    ++pqResumes;
    if (pqFairRefill)
    {
        pqParentPause(pqFixture);
        pqSend(pqFixture->mux, l, makePatternPayload(pqFixture, 1));
    }
}

static void pqDiscardSink(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    twfRequire(! pqTransportPaused, "fairness pump wrote through Pause");
    ++pqDeliveries;
    lineReuseBuffer(l, buf);
}

static void caseParentFairness(void)
{
    twfSetCase("2000 eligible children receive opportunities across interrupted release passes and churn");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t   *ts                 = tunnelGetState(f.mux);
    const uint32_t cost               = (uint32_t) pooledBufferCharge(f.env.pool, false);
    ts->parent_write_pause_threshold  = 2 * cost;
    ts->parent_write_resume_threshold = cost;
    ts->parent_write_limit            = 4 * cost;
    pq_state_t *parent                = lineGetState(f.parent_l, f.mux);
    /* Keep the fixture child peer-paused; it must never receive a local Resume. */
    pq_state_t *fixture_child = lineGetState(f.child_l, f.mux);
    discard     pqPeerPause(f.mux, f.parent_l, fixture_child, true, false);
    line_t    **children = memoryAllocate(2000 * sizeof(*children));
    for (unsigned i = 0; i < 2000; ++i)
        children[i] = pqSibling(&f, parent, 100 + i);
    pqSource(&f)->pqResumeSlot      = pqFairResume;
    pqParentSink(&f)->pqPayloadSlot = pqDiscardSink;
    memoryZero(pqFairSeen, sizeof(pqFairSeen));
    pqFairRefill = true;
    pqParentPause(&f);
    pqSend(f.mux, children[0], makePatternPayload(&f, 1));
    pqSend(f.mux, children[0], makePatternPayload(&f, 1));
    for (unsigned round = 0; round < 2; ++round)
    {
        for (unsigned i = 0; i < 2000; ++i)
        {
            const unsigned before = pqResumes;
            pqParentResume(&f);
            twfRequire(pqResumes == before + 1 && pqOutput(&f)->sources_throttled,
                       "interrupted pass resumed an obsolete remainder");
        }
        for (unsigned i = 0; i < 2000; ++i)
            twfRequire(pqFairSeen[i] == round + 1, "list position starved a stable eligible child");
    }
    /* Remove the cursor target and replace it while pressure remains active. */
    pq_state_t *target = parent->parent_state->resume_cursor;
    if (target == fixture_child)
        target = target->child_next ? target->child_next : parent->child_next;
    const unsigned removed = target->connection_id - 100;
    pqDestroySibling(&f, children[removed]);
    children[removed]                                                            = pqSibling(&f, parent, 100 + removed);
    ((pq_state_t *) lineGetState(children[removed], f.mux))->parent_write_paused = true;
    pqFairRefill                                                                 = false;
    pqParentResume(&f);
    twfRequire(! pqOutput(&f)->sources_throttled && fixture_child->peer_flow_paused &&
                   ! fixture_child->parent_write_paused,
               "final release erased peer gate or stranded output");
    for (unsigned i = 0; i < 2000; ++i)
        pqDestroySibling(&f, children[i]);
    memoryFree(children);
    twfRequire(parent->parent_state->resume_cursor == fixture_child, "cursor retained a removed child");
    fixtureTeardown(&f);
}

static unsigned pqResumeMutationMode;
static line_t  *pqMutationSibling;
static line_t  *pqMutationAdded;
static void     pqMutationResume(tunnel_t *t, line_t *l)
{
    discard t;
    ++pqResumes;
    if (pqResumes != 1)
        return;
    pq_state_t *parent = lineGetState(pqFixture->parent_l, pqFixture->mux);
    if (pqResumeMutationMode == 0)
    {
        pqFinish(pqFixture->mux, l);
#ifdef MUX_OUTPUT_CLIENT
        lineDestroy(l);
#endif
    }
    else if (pqResumeMutationMode == 1)
    {
        pqDestroySibling(pqFixture, pqMutationSibling);
        pqMutationSibling = NULL;
    }
    else if (pqResumeMutationMode == 2)
        pqLoss(pqFixture->mux, pqFixture->parent_l, true);
    else if (pqResumeMutationMode == 3)
        pqMutationAdded = pqSibling(pqFixture, parent, 102);
    else
    {
        pq_tstate_t *ts                = tunnelGetState(pqFixture->mux);
        ts->worker_states[0].quiescing = true;
    }
}

static void caseParentResumeMutation(unsigned mode)
{
    twfSetCase("nonempty release tolerates self/sibling removal, attachment, parent death and quiescence");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t   *ts                                               = tunnelGetState(f.mux);
    const uint32_t cost                                             = (uint32_t) pooledBufferCharge(f.env.pool, false);
    ts->parent_write_pause_threshold                                = 2 * cost;
    ts->parent_write_resume_threshold                               = cost;
    ts->parent_write_limit                                          = 8 * cost;
    pq_state_t *parent                                              = lineGetState(f.parent_l, f.mux);
    pqMutationSibling                                               = pqSibling(&f, parent, 101);
    ((pq_state_t *) lineGetState(pqMutationSibling, f.mux))->paused = false;
    pqMutationAdded                                                 = NULL;
    pqResumeMutationMode                                            = mode;
    pqSource(&f)->pqResumeSlot                                      = pqMutationResume;
    lineRef(f.parent_l);
    lineRef(f.child_l);
    pqParentPause(&f);
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    pqParentResume(&f);
    if (mode == 2)
    {
        twfRequireLineStateZeroed(f.parent_l, f.mux, "parent death retained output state");
#ifdef MUX_OUTPUT_CLIENT
        lineDestroy(pqMutationSibling); // Fake owner settles the borrowed sibling after Finish.
#endif
        pqMutationSibling = NULL;
    }
    else if (mode == 4)
    {
        twfRequire(pqResumes == 1 && pqOutput(&f)->charge == cost, "quiescence allowed payload or further Resume");
        ts->worker_states[0].quiescing = false; // Fixture cleanup only.
    }
    else
        twfRequire(pqOutput(&f)->charge == 0, "mutation stranded retained output");
    if (pqMutationAdded)
        pqDestroySibling(&f, pqMutationAdded);
    if (pqMutationSibling)
        pqDestroySibling(&f, pqMutationSibling);
    const bool parent_dead = ! lineIsAlive(f.parent_l);
    const bool child_dead  = ! lineIsAlive(f.child_l);
    lineUnref(f.child_l);
    lineUnref(f.parent_l);
    if (parent_dead)
        f.parent_l = NULL;
    if (child_dead)
        f.child_l = NULL;
    fixtureTeardown(&f);
}

static void caseParentThrottleClock(void)
{
    twfSetCase("throttle episodes use 64-bit monotonic time including zero start");
    mux_parent_output_t output  = {0};
    const uint64_t      elapsed = ((uint64_t) UINT32_MAX + 1234) * 1000;
    muxParentOutputSetThrottled(&output, true, 0);
    twfRequire(muxParentOutputThrottleMS(&output, elapsed) == elapsed / 1000, "long throttle duration truncated");
    muxParentOutputSetThrottled(&output, false, elapsed);
    twfRequire(output.last_throttle_us == elapsed && muxParentOutputThrottleMS(&output, elapsed) == 0,
               "completed episode duration lost");
    muxParentOutputSetThrottled(&output, true, elapsed + 1);
    muxParentOutputSetThrottled(&output, false, elapsed + 2001);
    twfRequire(output.last_throttle_us == 2000, "repeated episode did not replace last duration");
}

static void caseParentGate(unsigned children, bool resume_in_pause)
{
    twfSetCase("parent high water fans out once and releases only empty+writable");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts                  = tunnelGetState(f.mux);
    const size_t charge              = pooledBufferCharge(f.env.pool, false);
    ts->parent_write_pause_threshold = (uint32_t) (2 * charge);
    ts->parent_write_resume_threshold = 0;
    ts->parent_write_limit           = (uint32_t) (4 * charge);
    pq_state_t *parent               = lineGetState(f.parent_l, f.mux);
    line_t    **siblings             = memoryAllocate(children * sizeof(*siblings));
    for (unsigned i = 1; i < children; ++i)
        siblings[i] = pqSibling(&f, parent, 100 + i);
    pqParentPause(&f);
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    twfRequire(pqPauses == 0 && pqOutput(&f)->charge == charge, "below high water paused sources");
    pqResumeInPause = resume_in_pause;
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    twfRequire(pqPauses == children, "exact high water missed or duplicated fanout");
    if (! resume_in_pause)
    {
        pqParentPause(&f);
        pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
        twfRequire(pqPauses == children, "additional retained output repeated fanout");
        pqPauseAt = 3;
        pqParentResume(&f);
        twfRequire(pqOutput(&f)->charge == 0 && pqOutput(&f)->sources_throttled && pqResumes == 0,
                   "empty but paused transport released sources");
        pqParentResume(&f);
    }
    twfRequire(pqResumes == children && ! pqOutput(&f)->sources_throttled && pqOutput(&f)->charge == 0,
               "gate failed to settle after nested Resume");
    for (unsigned i = 1; i < children; ++i)
        pqDestroySibling(&f, siblings[i]);
    memoryFree(siblings);
    fixtureTeardown(&f);
}

static void caseParentGateMutation(void)
{
    twfSetCase("gate traversal survives sibling deletion and a fresh gate during Resume");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts                  = tunnelGetState(f.mux);
    const size_t charge              = pooledBufferCharge(f.env.pool, false);
    ts->parent_write_pause_threshold = (uint32_t) charge;
    ts->parent_write_resume_threshold = 0;
    ts->parent_write_limit           = (uint32_t) (4 * charge);
    pq_state_t *parent               = lineGetState(f.parent_l, f.mux);
    line_t     *victim               = pqSibling(&f, parent, 100);
    line_t     *survivor             = pqSibling(&f, parent, 101);
    pqRemoveOnPause                  = victim;
    pqPeerResumeUnvisited            = f.child_l;
    pqParentPause(&f);
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    twfRequire(pqPauses == 2 && parent->children_count == 2, "fanout visited a destroyed sibling");
    pqReblockOnResume = true;
    pqParentResume(&f);
    twfRequire(pqResumes == 1 && pqOutput(&f)->sources_throttled, "obsolete Resume pass released another source");
    pqParentResume(&f);
    twfRequire(! pqOutput(&f)->sources_throttled && pqResumes == 3, "new gate did not release exactly once");
    pq_state_t *child = lineGetState(f.child_l, f.mux);
    discard     pqPeerPause(f.mux, f.parent_l, child, true, false);
    pqParentPause(&f);
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    discard pqPeerResume(f.mux, f.parent_l, child, true, false);
    twfRequire(child->parent_write_paused, "peer Resume bypassed local gate");
    discard pqPeerPause(f.mux, f.parent_l, child, true, false);
    pqParentResume(&f);
    twfRequire(child->peer_flow_paused && ! child->parent_write_paused, "local release erased peer pressure");
    discard pqPeerResume(f.mux, f.parent_l, child, true, false);
    pqDestroySibling(&f, survivor);
    fixtureTeardown(&f);
}

static sbuf_t *pqChargedBuffer(size_t charge)
{
    const size_t overhead = sizeof(sbuf_t) + kSbufAllocationAlignment + 64;
    sbuf_t      *buf      = twfTrackAcquired(sbufCreateWithPadding((uint32_t) (charge - overhead), 64));
    twfRequire(sbufGetAllocationCharge(buf) == charge, "test charge geometry is not exact");
    sbufSetLength(buf, 1);
    sbufWriteUI8(buf, 17);
    return buf;
}

static void caseParentHardLimit(bool defaults, bool reservation_failure, bool shutdown)
{
    twfSetCase("parent output enforces inclusive allocation limit and releases backlog on local failure/Stop");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts = tunnelGetState(f.mux);
    if (! defaults)
    {
        ts->parent_write_pause_threshold = 8192;
        ts->parent_write_resume_threshold = 0;
        ts->parent_write_limit           = 16384;
    }
    const size_t threshold = ts->parent_write_pause_threshold;
    const size_t limit     = ts->parent_write_limit;
    pqParentPause(&f);
    pqSend(f.mux, f.child_l, pqChargedBuffer(threshold - 256));
    twfRequire(pqPauses == 0, "just below threshold paused sources");
    pqSend(f.mux, f.child_l, pqChargedBuffer(256));
    twfRequire(pqPauses == 1 && pqOutput(&f)->charge == threshold, "exact threshold missed fanout");
    pqSend(f.mux, f.child_l, pqChargedBuffer(limit - threshold));
    twfRequire(pqPauses == 1 && pqOutput(&f)->charge == limit, "exact hard limit was rejected");
    lineRef(f.parent_l);
    lineRef(f.child_l);
    if (shutdown)
    {
#ifdef MUX_OUTPUT_CLIENT
        pqStop(f.mux, 0, wwLifecycleProcessShutdown());
#else
        pqStop(f.mux, 0, wwLifecycleProcessShutdown());
        pqLoss(f.mux, f.parent_l, false); // actual borrowed-parent owner drives its Finish
#endif
    }
    else if (reservation_failure)
    {
        pqParentResume(&f);
        bufferqueueDestroy(&pqOutput(&f)->pending);
        bufferqueueInitEmpty(&pqOutput(&f)->pending);
        pqParentPause(&f);
        g_reject_next_queue_reallocation = true;
        pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
        twfRequire(! g_reject_next_queue_reallocation, "insertion refusal seam was not exercised");
    }
    else
        pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    twfRequireLineStateZeroed(f.parent_l, f.mux, "terminal output retained parent state");
    twfRequireLineStateZeroed(f.child_l, f.mux, "terminal output retained child state");
#ifdef MUX_OUTPUT_CLIENT
    twfRequire(! lineIsAlive(f.parent_l), "overflow left owned parent alive");
    lineUnref(f.parent_l);
    f.parent_l = NULL;
    lineUnref(f.child_l);
#else
    twfRequire(! lineIsAlive(f.child_l), "overflow left owned child alive");
    lineUnref(f.child_l);
    f.child_l = NULL;
    lineUnref(f.parent_l);
#endif
    twfRequireNoLeakedBuffers();
    fixtureTeardown(&f);
}

static cJSON *pqSettings(void)
{
#ifdef MUX_OUTPUT_CLIENT
    return cJSON_Parse("{\"mode\":\"counter\",\"connection-capacity\":100}");
#else
    return cJSON_Parse("{}");
#endif
}

static void caseParentWriteConfiguration(void)
{
    twfSetCase("both parent write settings are checked independently and used by their node instance");
    pq_fixture_t f;
    pqSetup(&f);
    GSTATE.ram_profile = kRamProfileL2Memory;
    const char *keys[] = {"parent-write-buffer-pause-threshold", "parent-write-buffer-limit"};
    const char *bad[]  = {"0", "-1", "1.5", "2147483648", "true", "null", "\"123\"", "[]", "{}"};
    for (unsigned key = 0; key < 2; ++key)
    {
        for (unsigned i = 0; i < ARRAY_SIZE(bad); ++i)
        {
            cJSON *settings = pqSettings();
            cJSON_AddItemToObject(settings, keys[key], cJSON_Parse(bad[i]));
            node_t node = {.node_settings_json = settings};
            twfRequire(pqCreate(&node) == NULL, "malformed parent write setting accepted");
            cJSON_Delete(settings);
        }
    }
    const uint32_t pairs[][2] = {
        {0, 0}, {4096, 0}, {0, 67108864}, {8192, 16384}, {16384, 16384}, {32768, 16384}, {0, 16384}};
    for (unsigned i = 0; i < ARRAY_SIZE(pairs); ++i)
    {
        cJSON *settings = pqSettings();
        for (unsigned key = 0; key < 2; ++key)
            if (pairs[i][key])
                cJSON_AddNumberToObject(settings, keys[key], pairs[i][key]);
        node_t    node = {.node_settings_json = settings};
        tunnel_t *mux  = pqCreate(&node);
        if (i >= 4)
            twfRequire(mux == NULL, "invalid effective threshold/limit pair accepted");
        else
        {
            twfRequire(mux != NULL, "valid parent write settings rejected");
            pq_tstate_t *ts = tunnelGetState(mux);
            twfRequire(ts->parent_write_pause_threshold == (pairs[i][0] ? pairs[i][0] : 16777216) &&
                           ts->parent_write_limit == (pairs[i][1] ? pairs[i][1] : 134217728),
                       "parent write independent defaults drifted");
            if (i == 0)
            {
                twfRequire(ts->parent_write_resume_threshold == 12582912, "default parent resume threshold drifted");
                twfRequire(ts->parent_buffer_limit == 134217728, "default parent receive limit drifted");
            }
            if (i == 3)
            {
                /* Run the existing real line fixture against the parsed instance. */
                tunnel_t    *original    = f.mux;
                pq_tstate_t *original_ts = tunnelGetState(original);
#ifdef MUX_OUTPUT_CLIENT
                ts->worker_states[0].owned_parents          = original_ts->worker_states[0].owned_parents;
                original_ts->worker_states[0].owned_parents = NULL;
#endif
                f.mux = mux;
                tunnelBind(f.prev, mux);
                tunnelBind(mux, f.next);
                pqParentPause(&f);
                pqSend(mux, f.child_l, pqChargedBuffer(8192));
                twfRequire(pqPauses == 1 && pqOutput(&f)->charge == 8192, "runtime ignored parsed threshold");
                pqSend(mux, f.child_l, pqChargedBuffer(8192));
                twfRequire(pqOutput(&f)->charge == 16384, "runtime rejected parsed hard-limit equality");
                lineRef(f.parent_l);
                lineRef(f.child_l);
                pqSend(mux, f.child_l, makePatternPayload(&f, 1));
                twfRequireLineStateZeroed(f.parent_l, mux, "runtime ignored parsed hard limit");
                twfRequireLineStateZeroed(f.child_l, mux, "parsed hard-limit cleanup retained child");
#ifdef MUX_OUTPUT_CLIENT
                twfRequire(! lineIsAlive(f.parent_l), "parsed limit did not close owned parent");
                lineUnref(f.parent_l);
                f.parent_l = NULL;
                lineUnref(f.child_l);
#else
                twfRequire(! lineIsAlive(f.child_l), "parsed limit did not close owned child");
                lineUnref(f.child_l);
                f.child_l = NULL;
                lineUnref(f.parent_l);
#endif
                twfRequire(original_ts->parent_write_pause_threshold == 16777216 &&
                               original_ts->parent_write_limit == 134217728,
                           "node instances shared settings");
                f.mux = original;
                tunnelBind(f.prev, original);
                tunnelBind(original, f.next);
            }
            pqDestroy(mux, wwLifecycleProcessShutdown());
        }
        cJSON_Delete(settings);
    }
    fixtureTeardown(&f);
}

static void caseParentResumeConfiguration(void)
{
    twfSetCase("strict effective pause/resume/limit tuple parsing");
    pq_fixture_t f;
    pqSetup(&f);
    const char *bad[] = {"-1", "1.5", "2147483648", "true", "false", "null", "\"0\"", "[]", "{}"};
    for (unsigned i = 0; i < ARRAY_SIZE(bad); ++i)
    {
        cJSON *settings = pqSettings();
        cJSON_AddItemToObject(settings, "parent-write-buffer-resume-threshold", cJSON_Parse(bad[i]));
        node_t node = {.node_settings_json = settings};
        twfRequire(pqCreate(&node) == NULL, "invalid resume type accepted");
        cJSON_Delete(settings);
    }
    const uint32_t tuples[][3] = {{1, 0, 2},
                                  {8388608, 7340032, 134217728},
                                  {INT_MAX - 1, INT_MAX - 2, INT_MAX},
                                  {2, 2, 3},
                                  {2, 3, 4},
                                  {2, 0, 2},
                                  {INT_MAX, 0, INT_MAX}};
    for (unsigned i = 0; i < ARRAY_SIZE(tuples); ++i)
    {
        cJSON *settings = pqSettings();
        cJSON_AddNumberToObject(settings, "parent-write-buffer-pause-threshold", tuples[i][0]);
        cJSON_AddNumberToObject(settings, "parent-write-buffer-resume-threshold", tuples[i][1]);
        cJSON_AddNumberToObject(settings, "parent-write-buffer-limit", tuples[i][2]);
        node_t    node = {.node_settings_json = settings};
        tunnel_t *mux  = pqCreate(&node);
        twfRequire((mux != NULL) == (i < 3), "incorrect tuple acceptance");
        if (mux)
        {
            pq_tstate_t *ts = tunnelGetState(mux);
            twfRequire(ts->parent_write_resume_threshold == tuples[i][1], "explicit resume changed");
            pqDestroy(mux, wwLifecycleProcessShutdown());
        }
        cJSON_Delete(settings);
    }
    const uint32_t derived[][2] = {{1, 0}, {3, 2}, {8388608, 6291456}, {16777216, 12582912}, {33554432, 25165824}};
    for (unsigned i = 0; i < ARRAY_SIZE(derived); ++i)
    {
        cJSON *settings = pqSettings();
        cJSON_AddNumberToObject(settings, "parent-write-buffer-pause-threshold", derived[i][0]);
        node_t    node = {.node_settings_json = settings};
        tunnel_t *mux  = pqCreate(&node);
        twfRequire(mux != NULL, "derived resume rejected");
        pq_tstate_t *ts = tunnelGetState(mux);
        twfRequire(ts->parent_write_resume_threshold == derived[i][1], "derived resume incorrect");
        pqDestroy(mux, wwLifecycleProcessShutdown());
        cJSON_Delete(settings);
    }
    fixtureTeardown(&f);
}

static void caseParentQueuedChildClose(bool with_data)
{
    twfSetCase("encoded output survives local child Finish");
    pq_fixture_t f;
    pqSetup(&f);
    pqParentPause(&f);
    if (with_data)
    {
        sbuf_t *buf = makePatternPayload(&f, 1);
        pqSend(f.mux, f.child_l, buf);
    }
    lineRef(f.child_l);
    pqFinish(f.mux, f.child_l);
    twfRequire(pqDeliveries == 0, "child Close bypassed Pause");
    twfRequireLineStateZeroed(f.child_l, f.mux, "local Finish retained child state");
#ifndef MUX_OUTPUT_CLIENT
    twfRequire(! lineIsAlive(f.child_l), "local Finish left owned child alive");
    lineUnref(f.child_l);
    f.child_l = NULL;
#else
    lineUnref(f.child_l);
#endif
    pqParentResume(&f);
    twfRequire(pqOutput(&f)->charge == 0, "drain leaked output charge");
    frame_view_t frames[4];
    unsigned     count = parseFrames(f.capture, f.trace.capture_len, frames, 4);
#ifdef MUX_OUTPUT_CLIENT
    twfRequire(count == (with_data ? 3U : 2U) && frames[0].flags == kMuxFlagOpen,
               "queued close lost or duplicated Open");
#else
    twfRequire(count == (with_data ? 2U : 1U), "queued close duplicated a frame");
#endif
    twfRequire(frames[count - 1].flags == kMuxFlagClose, "Close did not follow prior output");
    fixtureTeardown(&f);
}

static void caseParentAdmissionArithmeticAndDirect(void)
{
    twfSetCase("retention arithmetic rejects overflow while writable direct output has no retention bound");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts                  = tunnelGetState(f.mux);
    ts->parent_write_pause_threshold = 1;
    ts->parent_write_resume_threshold = 0;
    ts->parent_write_limit           = 2;
    pqSend(f.mux, f.child_l, makePatternPayload(&f, 1));
    twfRequire(pqDeliveries == 1 && pqOutput(&f)->pending.q.cbuf == NULL,
               "direct path allocated a queue or applied the retention limit");
    mux_parent_output_t output = {0};
    bufferqueueInitEmpty(&output.pending);
    output.charge    = SIZE_MAX - 4;
    sbuf_t *buf      = makePatternPayload(&f, 0);
    sbuf_t *original = buf;
    twfRequire(! muxParentOutputEnqueue(&output, &buf, SIZE_MAX) && original == buf &&
                   bufferqueueGetBufCount(&output.pending) == 0,
               "overflowing admission changed ownership");
    lineReuseBuffer(f.parent_l, buf);
    bufferqueueDestroy(&output.pending);
    fixtureTeardown(&f);
}

static void caseQueueLimitCloseCannotReenterChild(void)
{
    twfSetCase("incoming queue-limit Close cannot notify or close its destroyed child twice");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts                  = tunnelGetState(f.mux);
    ts->parent_write_pause_threshold = 1;
    ts->parent_write_resume_threshold = 0;
    ts->child_buffer_limit           = 1;
    pq_state_t *parent               = lineGetState(f.parent_l, f.mux);
    pq_state_t *child                = lineGetState(f.child_l, f.mux);
#ifdef MUX_OUTPUT_CLIENT
    child->open_frame_submitted = true;
#endif
    child->paused      = true;
    line_t *sibling    = pqSibling(&f, parent, 100);
    pqCloseSelfOnPause = true;
    pqParentPause(&f);
    lineRef(f.child_l);
    discard pqQueue(f.mux, f.parent_l, ts, parent, child, makePatternPayload(&f, 1));
    twfRequireLineStateZeroed(f.child_l, f.mux, "queue-limit victim state survived Close");
    twfRequire(pqPauses == 1, "queue-limit Close notified its own terminal child");
#ifndef MUX_OUTPUT_CLIENT
    lineUnref(f.child_l);
    f.child_l = NULL;
#else
    lineUnref(f.child_l);
#endif
    pqParentResume(&f);
    frame_view_t   frames[2];
    const unsigned count = parseFrames(f.capture, f.trace.capture_len, frames, 2);
    twfRequire(count == 1 && frames[0].flags == kMuxFlagClose && frames[0].cid == kTestChildCid,
               "reentrant pressure duplicated Close");
    pqDestroySibling(&f, sibling);
    fixtureTeardown(&f);
}

static void pqPauseOnReceive(tunnel_t *t, line_t *l, sbuf_t *buf)
{
#ifdef MUX_OUTPUT_CLIENT
    twfPrevPayload(t, l, buf);
    if (l == pqFixture->child_l)
        muxclientTunnelUpStreamPause(pqFixture->mux, l);
#else
    twfNextPayload(t, l, buf);
    if (l == pqFixture->child_l)
        muxserverTunnelDownStreamPause(pqFixture->mux, l);
#endif
}

static void caseChildCloseKeepsParentParsing(void)
{
    twfSetCase("queued FlowPause may close one child without stranding a sibling frame");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts                  = tunnelGetState(f.mux);
    ts->parent_write_pause_threshold  = 1;
    ts->parent_write_resume_threshold = 0;
    pq_state_t *parent               = lineGetState(f.parent_l, f.mux);
    pq_state_t *child                = lineGetState(f.child_l, f.mux);
#ifdef MUX_OUTPUT_CLIENT
    child->open_frame_submitted = true;
    f.prev->fnPayloadD          = pqPauseOnReceive;
#else
    discard child;
    f.next->fnPayloadU = pqPauseOnReceive;
#endif
    line_t *sibling                                       = pqSibling(&f, parent, 100);
    ((pq_state_t *) lineGetState(sibling, f.mux))->paused = false;
    pqCloseSelfOnPause                                    = true;
    pqParentPause(&f);
    lineRef(f.child_l);

    const uint32_t frame_size = kMuxFrameLength + 1;
    sbuf_t        *batch      = makePatternPayload(&f, 2 * frame_size);
    uint8_t       *data       = sbufGetMutablePtr(batch);
    writeFrameHeader(data, 1, kMuxFlagData, kTestChildCid);
    data[kMuxFrameLength] = 17;
    writeFrameHeader(data + frame_size, 1, kMuxFlagData, 100);
    data[frame_size + kMuxFrameLength] = 34;
    pqReceive(f.mux, f.parent_l, batch);

    twfRequire(lineIsAlive(f.parent_l) && ! lineIsAlive(f.child_l), "Pause did not close only its child");
    twfRequire(splicestreamLength(parent->parent_state->read_stream) == 0, "complete sibling frame remained stranded");
    twfRequire(pqChildDeliveries(&f) == 2 && f.trace.capture_len == 2 && f.capture[0] == 17 && f.capture[1] == 34,
               "sibling payload was not delivered immediately and intact");
    twfRequire(parent->pending_child_queue_charge == 0, "closed child's incoming queue charge was retained");

    lineUnref(f.child_l);
    f.child_l          = sibling;
    pqCloseSelfOnPause = false;
    fixtureTeardown(&f);
}

#if WW_HAVE_SPLICE
#include "splice_buffer.h"
#include <sys/ioctl.h>

static unsigned pqSpliceParentDeliveries;
static unsigned pqSpliceChildDeliveries;
static int      pqExpectSpliceChild;
static uint32_t pqExpectedChildLength;
static int      pqExpectedPipe;

static sbuf_t *pqSpliceBytes(pq_fixture_t *f, const uint8_t *bytes, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetSpliceBuffer(f->env.pool);
    twfRequire(buf != NULL, "failed to allocate private-pipe fixture");
    const int fd     = sbufSpliceMetadata(buf).pipefd[1];
    uint32_t  offset = 0;
    while (offset < length)
    {
        ssize_t n = write(fd, bytes + offset, length - offset);
        if (n < 0 && errno == EINTR)
            continue;
        twfRequire(n > 0, "private pipe could not hold the complete fixture payload");
        offset += (uint32_t) n;
    }
    buf->capacity = buf->l_pad + length;
    sbufSetLength(buf, length);
    return buf;
}

static sbuf_t *pqSplicePattern(pq_fixture_t *f, uint32_t length)
{
    uint8_t bytes[128];
    twfRequire(length <= sizeof(bytes), "splice pattern fixture is too large");
    for (uint32_t i = 0; i < length; ++i)
        bytes[i] = patternByte(i);
    return pqSpliceBytes(f, bytes, length);
}

static int      pqParentPipeFDs[2];
static unsigned pqParentPipeFDCount;

static void pqSpliceParentSink(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    if ((buf->flags & kSbufFlagSplice) != 0)
    {
        ++pqSpliceParentDeliveries;
        twfRequire(pqParentPipeFDCount == 0 || pqSpliceParentDeliveries <= pqParentPipeFDCount,
                   "parent emitted an unexpected private pipe");
        const int expected = pqParentPipeFDCount == 0 ? pqExpectedPipe : pqParentPipeFDs[pqSpliceParentDeliveries - 1U];
        twfRequire(sbufSpliceMetadata(buf).pipefd[0] == expected,
                   "parent output replaced or reordered the original private pipe");
        buf = muxMaterializeRetainedPayload(lineGetBufferPool(l), buf);
    }
    pqSink(t, l, buf);
}

static void pqSpliceChildSink(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    ++pqSpliceChildDeliveries;
    const bool opaque = (buf->flags & kSbufFlagSplice) != 0;
    twfRequire(pqExpectSpliceChild < 0 || opaque == (pqExpectSpliceChild != 0),
               "decoded child representation violates its delivery contract");
    if (opaque)
    {
        twfRequire(pqExpectedPipe < 0 || sbufSpliceMetadata(buf).pipefd[0] == pqExpectedPipe,
                   "direct child delivery replaced the original private pipe");
        buf = muxMaterializeRetainedPayload(lineGetBufferPool(l), buf);
    }
    twfRequire(sbufGetLength(buf) == pqExpectedChildLength, "decoded child frame length changed");
    for (uint32_t i = 0; i < pqExpectedChildLength; ++i)
        twfRequire(((const uint8_t *) sbufGetRawPtr(buf))[i] == patternByte(i),
                   "decoded child payload differs from the pipe input");
    lineReuseBuffer(l, buf);
}

static void pqSetSpliceSinks(pq_fixture_t *f)
{
    pqSpliceParentDeliveries = pqSpliceChildDeliveries = 0;
    pqParentPipeFDCount                                = 0;
    pqMaterializedBodyBytes                            = 0;
    pqParentSink(f)->pqPayloadSlot                     = pqSpliceParentSink;
#ifdef MUX_OUTPUT_CLIENT
    f->prev->fnPayloadD                                                     = pqSpliceChildSink;
    ((pq_state_t *) lineGetState(f->child_l, f->mux))->open_frame_submitted = true;
#else
    f->next->fnPayloadU = pqSpliceChildSink;
#endif
}

static void pqResumeDecodedChild(pq_fixture_t *f)
{
#ifdef MUX_OUTPUT_CLIENT
    muxclientTunnelUpStreamResume(f->mux, f->child_l);
#else
    muxserverTunnelDownStreamResume(f->mux, f->child_l);
#endif
}

/* Exercise the real node callbacks, not only the shared wire helpers. */
static void caseSpliceDecodedFrames(bool paused, bool header_in_pipe, uint32_t length)
{
    twfSetCase("complete Mux frames preserve eligible pipes for forwarding and paused retention");
    pq_fixture_t f;
    pqSetup(&f);
    pqSetSpliceSinks(&f);
    pq_state_t *child  = lineGetState(f.child_l, f.mux);
    pq_state_t *parent = lineGetState(f.parent_l, f.mux);
    child->paused      = paused;
    uint8_t wire[kMuxFrameLength + 64];
    writeFrameHeader(wire, length, kMuxFlagData, kTestChildCid);
    for (uint32_t i = 0; i < length; ++i)
        wire[kMuxFrameLength + i] = patternByte(i);
    sbuf_t *input = header_in_pipe ? pqSpliceBytes(&f, wire, kMuxFrameLength + length)
                                   : pqSpliceBytes(&f, wire + kMuxFrameLength, length);
    if (! header_in_pipe)
    {
        sbufShiftLeft(input, kMuxFrameLength);
        sbufWrite(input, wire, kMuxFrameLength);
    }
    pqExpectedPipe        = sbufSpliceMetadata(input).pipefd[0];
    pqExpectedChildLength = length;
    pqExpectSpliceChild   = length != 0;
    pqReceive(f.mux, f.parent_l, input);
    /* For a paused frame only the eight-byte wire header, when originally in
     * the pipe, may have been read. The body remains untouched until Resume. */
    if (paused)
        twfRequire(pqMaterializedBodyBytes == (header_in_pipe ? kMuxFrameLength : 0U),
                   "eligible decoded retention materialized body bytes before Resume");
    twfRequire((splicestreamLength(parent->parent_state->read_stream) == 0),
               "complete frame remained in the carrier stream");
    if (paused)
    {
        const sbuf_t *queued = bufferqueueFront(&child->pending_child_data);
        twfRequire(pqSpliceChildDeliveries == 0 && queued != NULL &&
                       ((queued->flags & kSbufFlagSplice) != 0) == (length != 0),
                   "paused child violated retained representation or delivered through Pause");
        const size_t cost = sbufGetQueueCharge(queued);
        requireEqualCharge(
            child->pending_child_queue_charge, cost, "paused splice frame omitted its queue-capacity charge");
        requireEqualCharge(
            parent->pending_child_queue_charge, cost, "attached-parent aggregate omitted queued splice capacity");

        if (length != 0)
            twfRequire(queued == input && sbufSpliceMetadata(queued).pipefd[0] == pqExpectedPipe,
                       "paused frame did not retain its original wrapper and pipe");
        int available = -1;
        twfRequire(ioctl(pqExpectedPipe, FIONREAD, &available) == 0 && available == (int) length,
                   "eligible queued frame consumed its private body before Resume");
        pqResumeDecodedChild(&f);
        twfRequire(child->pending_child_queue_charge == 0 && parent->pending_child_queue_charge == 0,
                   "Resume did not settle child and parent queue charges");
    }
    twfRequire(pqSpliceChildDeliveries == 1, "Data was not delivered exactly once, including empty Data");
    fixtureTeardown(&f);
}

static sbuf_t *pqTinyCarrierByte(pq_fixture_t *f, uint32_t index, bool splice_input)
{
    const uint8_t byte = patternByte(index);
    if (splice_input)
        return pqSpliceBytes(f, &byte, 1);
    sbuf_t *buf = bufferpoolGetSmallBuffer(f->env.pool);
    sbufSetLength(buf, 1);
    sbufWriteUI8(buf, byte);
    return buf;
}

static void caseSpliceManyIncompleteFragments(bool splice_input, bool complete, bool paused_child)
{
    twfSetCase("many tiny carrier fragments compact only at parent receive pressure");
    pq_fixture_t f;
    pqSetup(&f);
    pqSetSpliceSinks(&f);
    pq_state_t *parent                                           = lineGetState(f.parent_l, f.mux);
    pq_state_t *child                                            = lineGetState(f.child_l, f.mux);
    child->paused                                                = paused_child;
    sbuf_t        *header                                        = bufferpoolGetSmallBuffer(f.env.pool);
    const uint32_t payload_length                                = 160;
    ((pq_tstate_t *) tunnelGetState(f.mux))->parent_buffer_limit = 8192;
    twfRequire(payload_length <= kMuxMaxDataFrameLength, "tiny-carrier fixture exceeds one frame");
    sbufSetLength(header, kMuxFrameLength);
    writeFrameHeader(sbufGetMutablePtr(header), payload_length, kMuxFlagData, kTestChildCid);
    pqExpectedChildLength = payload_length;
    pqExpectSpliceChild   = -1;
    pqExpectedPipe        = -1;
    pqReceive(f.mux, f.parent_l, header);
    for (uint32_t n = 1; n < payload_length; ++n)
    {
        pqReceive(f.mux, f.parent_l, pqTinyCarrierByte(&f, n - 1U, splice_input));
        splice_stream_t *stream = parent->parent_state->read_stream;
        twfRequire(splicestreamLength(stream) == kMuxFrameLength + n, "fragment retention changed carrier byte count");
        twfRequire(pqSpliceChildDeliveries == 0 && child->pending_child_queue_charge == 0 &&
                       parent->pending_child_queue_charge == 0,
                   "incomplete frame was delivered or charged as a decoded child frame");

        const size_t entries = bufferqueueGetBufCount(&stream->pending) + (stream->head != NULL);
        twfRequire(entries <= n && splicestreamCharge(stream) < 8192,
                   "incoming fragments exceeded the configured receive budget");
    }
    if (complete)
    {
        pqReceive(f.mux, f.parent_l, pqTinyCarrierByte(&f, payload_length - 1U, splice_input));
        twfRequire((splicestreamLength(parent->parent_state->read_stream) == 0),
                   "completed carrier frame remained retained");
        if (paused_child)
        {
            twfRequire(pqSpliceChildDeliveries == 0 && bufferqueueGetBufCount(&child->pending_child_data) == 1,
                       "completed fragmented frame crossed Pause or lost its boundary");
            const sbuf_t *queued = bufferqueueFront(&child->pending_child_data);
            requireEqualCharge(child->pending_child_queue_charge,
                               sbufGetQueueCharge(queued),
                               "completed paused frame charge does not match retained allocation");
            pqResumeDecodedChild(&f);
        }
        twfRequire(pqSpliceChildDeliveries == 1 && child->pending_child_queue_charge == 0 &&
                       parent->pending_child_queue_charge == 0,
                   "completed frame did not deliver once and settle its charge");
    }
    /* Also exercise destruction before the declared frame is complete. */
    fixtureTeardown(&f);
}

static void caseSpliceIncompleteCarrier(void)
{
    twfSetCase("incomplete splice headers and bodies retain bounded pipes between callbacks");
    for (uint32_t split = 0; split <= 32; ++split)
    {
        pq_fixture_t f;
        pqSetup(&f);
        pqSetSpliceSinks(&f);
        uint8_t wire[40];
        writeFrameHeader(wire, 32, kMuxFlagData, kTestChildCid);
        for (uint32_t i = 0; i < 32; ++i)
            wire[kMuxFrameLength + i] = patternByte(i);
        pqExpectedChildLength = 32;
        pqExpectSpliceChild   = split == 0 || split == 8;
        pqReceive(f.mux, f.parent_l, pqSpliceBytes(&f, wire, split));
        pq_state_t *parent = lineGetState(f.parent_l, f.mux);
        twfRequire(pqSpliceChildDeliveries == 0 && parent->parent_state->read_stream->total == split,
                   "incomplete carrier was consumed as a complete frame");

        sbuf_t *rest        = pqSpliceBytes(&f, wire + split, sizeof(wire) - split);
        pqExpectedPipe      = split <= 8 ? sbufSpliceMetadata(rest).pipefd[0] : -1;
        pqExpectSpliceChild = true;
        pqReceive(f.mux, f.parent_l, rest);
        twfRequire(pqSpliceChildDeliveries == 1 && parent->parent_state->read_stream->total == 0,
                   "fragmented splice frame failed to finish in FIFO order");
        fixtureTeardown(&f);
    }
}

static void caseSpliceParentOutput(bool paused)
{
    twfSetCase("splice parent output obeys Pause, control ordering and queue-capacity limits");
    pq_fixture_t f;
    pqSetup(&f);
    pqSetSpliceSinks(&f);
#ifdef MUX_OUTPUT_CLIENT
    ((pq_state_t *) lineGetState(f.child_l, f.mux))->open_frame_submitted = false;
#endif
    if (paused)
        pqParentPause(&f);
    sbuf_t *input       = pqSplicePattern(&f, 32);
    pqExpectedPipe      = sbufSpliceMetadata(input).pipefd[0];
    pqParentPipeFDs[0]  = pqExpectedPipe;
    pqParentPipeFDCount = 1;
    pqSend(f.mux, f.child_l, input);
    if (paused)
    {
        const sbuf_t *retained = bufferqueueFront(&pqOutput(&f)->pending);
        twfRequire(retained == input && (retained->flags & kSbufFlagSplice) != 0 && pqDeliveries == 0,
                   "parent failed to retain its original pipe or wrote through Pause");
        const size_t cost = sbufGetQueueCharge(retained);
        requireEqualCharge(
            pqOutput(&f)->charge, cost, "parent splice output omitted logical capacity from queue charge");
        twfRequire(pqMaterializedBodyBytes == 0, "paused parent materialized its body");
        int available = -1;
        twfRequire(ioctl(pqExpectedPipe, FIONREAD, &available) == 0 && available == 32,
                   "queued parent body was consumed before Resume");
        pq_state_t *parent = lineGetState(f.parent_l, f.mux);
        twfRequire(pqControl(f.mux, f.parent_l, parent, f.child_l, kTestChildCid, kMuxFlagFlowPause),
                   "interleaved control could not enter paused output");
        sbuf_t *second      = pqSplicePattern(&f, 17);
        pqParentPipeFDs[1]  = sbufSpliceMetadata(second).pipefd[0];
        pqParentPipeFDCount = 2;
        pqSend(f.mux, f.child_l, second);
        twfRequire(pqMaterializedBodyBytes == 0,
                   "interleaved control consumed a queued body or changed queue accounting");
        twfRequire(ioctl(pqParentPipeFDs[1], FIONREAD, &available) == 0 && available == 17,
                   "second queued parent body was consumed before Resume");
        pqPauseAt = 1;
        pqParentResume(&f);
        twfRequire(pqDeliveries == 1 && pqOutput(&f)->charge != 0,
                   "Pause during pipe drain lost residual ownership or allowed another Payload");
        pqPauseAt = 0;
        pqParentResume(&f);
        twfRequire(pqOutput(&f)->charge == 0 && pqSpliceParentDeliveries == 2,
                   "queued output did not drain and settle its retained pipes");
    }
    else
        twfRequire(pqSpliceParentDeliveries == 1, "writable output unnecessarily materialized a fitting pipe body");
    frame_view_t frames[5];
    uint32_t     n = parseFrames(f.capture, f.trace.capture_len, frames, 5);
#ifdef MUX_OUTPUT_CLIENT
    twfRequire(frames[0].flags == kMuxFlagOpen, "splice first output lost Open-before-Data");
    const uint32_t first = 1;
#else
    const uint32_t first = 0;
#endif
    twfRequire(n == first + (paused ? 3U : 1U) && frames[first].length == 32,
               "splice parent encoding changed frame boundaries");
    for (uint32_t i = 0; i < 32; ++i)
        twfRequire(frames[first].data[i] == patternByte(i), "splice parent output changed bytes");
    if (paused)
        twfRequire(frames[first + 1].flags == kMuxFlagFlowPause && frames[first + 2].length == 17,
                   "parent control overtook or interrupted retained Data");
    fixtureTeardown(&f);
}

static void caseSpliceParentRefusal(void)
{
    twfSetCase("queue refusal settles the owned splice candidate and closes only its parent");
    pq_fixture_t f;
    pqSetup(&f);
    pqSetSpliceSinks(&f);
    pqParentPause(&f);
    lineRef(f.parent_l);
    lineRef(f.child_l);
    sbuf_t   *input                  = pqSplicePattern(&f, 32);
    const int fd                     = sbufSpliceMetadata(input).pipefd[0];
    g_reject_next_queue_reallocation = true;
    pqSend(f.mux, f.child_l, input);
    twfRequire(! g_reject_next_queue_reallocation, "splice queue refusal seam was not reached");
    twfRequireLineStateZeroed(f.parent_l, f.mux, "splice refusal left parent state retained");
    twfRequireLineStateZeroed(f.child_l, f.mux, "splice refusal left child state retained");
    int available = -1;
    twfRequire(ioctl(fd, FIONREAD, &available) == 0 && available == 0,
               "splice refusal failed to drain the original private pipe");
#ifdef MUX_OUTPUT_CLIENT
    twfRequire(! lineIsAlive(f.parent_l), "splice refusal left owned parent alive");
    lineUnref(f.parent_l);
    f.parent_l = NULL;
    lineUnref(f.child_l);
#else
    twfRequire(! lineIsAlive(f.child_l), "splice refusal left owned child alive");
    lineUnref(f.child_l);
    f.child_l = NULL;
    lineUnref(f.parent_l);
#endif
    twfRequireNoLeakedBuffers();
    fixtureTeardown(&f);
}
#endif

#if WW_HAVE_SPLICE
/* Exercise real admission and drain/discard/detach after enabling bounded
 * retention. Ordinary and incomplete-carrier regressions remain independent. */

static void pqAccountingChildSink(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pq_state_t *child = lineGetState(l, pqFixture->mux);
    twfRequire(child->pending_child_queue_charge == 0, "popped child charge was not released before callback");
    pqSpliceChildSink(t, l, buf);
}

static void caseAccountedSpliceLifecycle(unsigned detach, bool discard_queue)
{
    twfSetCase("accounted child pipes settle through attached/detached drain and discard");
    pq_fixture_t f;
    pqSetup(&f);
    pqSetSpliceSinks(&f);
#ifdef MUX_OUTPUT_CLIENT
    f.prev->fnPayloadD = pqAccountingChildSink;
#else
    f.next->fnPayloadU = pqAccountingChildSink;
#endif
    pq_state_t *child  = lineGetState(f.child_l, f.mux);
    pq_state_t *parent = lineGetState(f.parent_l, f.mux);

    child->paused         = true;
    sbuf_t *buf           = pqSplicePattern(&f, 32);
    pqExpectedPipe        = sbufSpliceMetadata(buf).pipefd[0];
    pqExpectedChildLength = 32;
    pqExpectSpliceChild   = true;
    const size_t cost     = sbufGetQueueCharge(buf);

    pq_tstate_t *ts_admission = tunnelGetState(f.mux);
    twfRequire(pqQueue(f.mux, f.parent_l, ts_admission, parent, child, buf),
               "real child admission rejected a within-budget pipe");
    twfRequire(bufferqueueFront(&child->pending_child_data) == buf && child->pending_child_queue_charge == cost &&
                   parent->pending_child_queue_charge == cost && pqMaterializedBodyBytes == 0,
               "real admission replaced a pipe, read its body, or published incorrect resource counters");

    lineRef(f.child_l);
    if (detach)
    {
        lineRef(f.parent_l);
        if (detach == 2)
        {
            uint8_t invalid[kMuxFrameLength];
            writeFrameHeader(invalid, kMuxMaxDataFrameLength + 1U, kMuxFlagData, kTestChildCid);
            pqReceive(f.mux, f.parent_l, pqSpliceBytes(&f, invalid, sizeof(invalid)));
        }
        else
            pqLoss(f.mux, f.parent_l, false);
        twfRequireLineStateZeroed(f.parent_l, f.mux, "parent loss retained its own state");
#ifdef MUX_OUTPUT_CLIENT
        twfRequire(! lineIsAlive(f.parent_l), "parent loss did not destroy the owned client parent");
#endif
        lineUnref(f.parent_l);
#ifdef MUX_OUTPUT_CLIENT
        f.parent_l = NULL;
#endif
        twfRequire(child->parent == NULL && child->pending_child_queue_charge == cost,
                   "detaching a child released or duplicated its retained queue charge");
#ifdef MUX_OUTPUT_CLIENT
        pq_tstate_t *ts = tunnelGetState(f.mux);
        twfRequire(ts->detached_queued_charge[lineGetWID(f.child_l)] == cost,
                   "client detached queue charge omitted logical splice capacity");
#else
        twfRequire(muxserverGetDetachedRegistry(f.mux, f.child_l)->queued_charge == cost,
                   "server detached queue charge omitted logical splice capacity");
#endif
    }
    int available = -1;
    twfRequire(ioctl(pqExpectedPipe, FIONREAD, &available) == 0 && available == 32 && pqSpliceChildDeliveries == 0,
               "queued child pipe was materialized or delivered before Resume");
    if (discard_queue)
        pqFinish(f.mux, f.child_l);
    else
        pqResumeDecodedChild(&f);

    twfRequire(pqSpliceChildDeliveries == (discard_queue ? 0U : 1U),
               "child settlement delivered the wrong number of frames");
#ifndef MUX_OUTPUT_CLIENT
    const bool child_dead = ! lineIsAlive(f.child_l);
#endif
    twfRequire(child->pending_child_queue_charge == 0, "child cleanup retained queue capacity charge");
    lineUnref(f.child_l);
#ifndef MUX_OUTPUT_CLIENT
    if (child_dead)
        f.child_l = NULL;
#endif
    fixtureTeardown(&f);
}

static void caseAccountedSpliceReservationFailure(void)
{
    twfSetCase("transactional parent reservation failure publishes no pipe cost and consumes no body");
    pq_fixture_t f;
    pqSetup(&f);
    mux_parent_output_t output = {0};
    bufferqueueInitEmpty(&output.pending);

    sbuf_t   *buf                    = pqSplicePattern(&f, 32);
    sbuf_t   *original               = buf;
    const int fd                     = sbufSpliceMetadata(buf).pipefd[0];
    g_reject_next_queue_reallocation = true;
    twfRequire(! muxParentOutputEnqueue(&output, &buf, SIZE_MAX), "refused reservation admitted a pipe");
    int available = -1;
    twfRequire(! g_reject_next_queue_reallocation && buf == original && output.charge == 0 &&
                   bufferqueueGetBufCount(&output.pending) == 0 && ioctl(fd, FIONREAD, &available) == 0 &&
                   available == 32,
               "failed parent admission changed candidate ownership, body, or resource counters");
    lineReuseBuffer(f.child_l, buf);
    muxParentOutputDestroy(&output, f.env.pool);
    fixtureTeardown(&f);
}
#endif

#if WW_HAVE_SPLICE
static bool pqHaveMaximumPipe(pq_fixture_t *f)
{
    sbuf_t    *pipe      = bufferpoolGetSpliceBuffer(f->env.pool);
    const bool available = pipe != NULL && sbufSpliceMetadata(pipe).pipe_capacity >= kMuxMaxDataFrameLength;
    if (pipe != NULL)
        bufferpoolReuseBuffer(f->env.pool, pipe);
    if (! available)
        fprintf(stderr, "SKIP: maximum Mux splice wrapper/batch requires a real 1048576-byte pipe\n");
    return available;
}

static void pqMaximumFittingSink(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    twfRequire(pqMaterializedBodyBytes == 0 && (buf->flags & kSbufFlagSplice) != 0,
               "fitting maximum splice path materialized the body before delivery");
    pqSpliceParentSink(t, l, buf); // Sink verification reads are intentionally excluded above.
}

static void caseMaximumFittingSplice(void)
{
    twfSetCase("a maximum fitting splice body stays in its original wrapper without materialization");
    pq_fixture_t f;
    pqSetup(&f);
    if (! pqHaveMaximumPipe(&f))
    {
        fixtureTeardown(&f);
        return;
    }
    f.capture                = memoryReAllocate(f.capture, kMuxMaxBufferedFrameLength);
    f.trace.capture          = f.capture;
    f.trace.capture_capacity = kMuxMaxBufferedFrameLength;
    pqSetSpliceSinks(&f);
    pqParentSink(&f)->pqPayloadSlot = pqMaximumFittingSink;
    uint8_t *bytes                  = memoryAllocate(kMuxMaxDataFrameLength);
    for (uint32_t i = 0; i < kMuxMaxDataFrameLength; ++i)
        bytes[i] = patternByte(i);
    sbuf_t *input  = pqSpliceBytes(&f, bytes, kMuxMaxDataFrameLength);
    pqExpectedPipe = sbufSpliceMetadata(input).pipefd[0];
    pqSend(f.mux, f.child_l, input);
    frame_view_t frame[1];
    twfRequire(pqDeliveries == 1 && parseFrames(f.capture, f.trace.capture_len, frame, 1) == 1 &&
                   frame[0].length == kMuxMaxDataFrameLength &&
                   memcmp(frame[0].data, bytes, kMuxMaxDataFrameLength) == 0,
               "maximum fitting splice frame was split or corrupted");
    memoryFree(bytes);
    fixtureTeardown(&f);
}
#endif

#include "mux_bounded_retention_cases.h"
#include "mux_splice_batch_cases.h"

static void caseChildPauseWithoutQueuedData(void)
{
    twfSetCase("child Pause/Resume signals the peer immediately without queued data or duplicate controls");
    pq_fixture_t f;
    pqSetup(&f);
    pq_state_t *child = lineGetState(f.child_l, f.mux);
#ifdef MUX_OUTPUT_CLIENT
    child->open_frame_submitted = true;
    muxclientTunnelUpStreamPause(f.mux, f.child_l);
    muxclientTunnelUpStreamPause(f.mux, f.child_l);
#else
    muxserverTunnelDownStreamPause(f.mux, f.child_l);
    muxserverTunnelDownStreamPause(f.mux, f.child_l);
#endif
    frame_view_t frames[2];
    twfRequire(child->paused && child->flow_paused_sent && bufferqueueGetBufCount(&child->pending_child_data) == 0 &&
                   parseFrames(f.capture, f.trace.capture_len, frames, 2) == 1 &&
                   frames[0].flags == kMuxFlagFlowPause && frames[0].cid == kTestChildCid,
               "child Pause waited for buffered data or sent duplicate FlowPause");
#ifdef MUX_OUTPUT_CLIENT
    muxclientTunnelUpStreamResume(f.mux, f.child_l);
    muxclientTunnelUpStreamResume(f.mux, f.child_l);
#else
    muxserverTunnelDownStreamResume(f.mux, f.child_l);
    muxserverTunnelDownStreamResume(f.mux, f.child_l);
#endif
    twfRequire(! child->paused && ! child->flow_paused_sent &&
                   parseFrames(f.capture, f.trace.capture_len, frames, 2) == 2 &&
                   frames[1].flags == kMuxFlagFlowResume && frames[1].cid == kTestChildCid,
               "child Resume lost or duplicated its matching FlowResume");
    fixtureTeardown(&f);
}

#ifdef MUX_OUTPUT_CLIENT
static unsigned pqOpeningPauseMode;

static void pqOpeningPauseSink(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    if (sbufIsSplice(buf))
        buf = muxMaterializeRetainedPayload(lineGetBufferPool(l), buf);
    pqSink(t, l, buf);
    if (pqDeliveries != 1)
        return;
    switch (pqOpeningPauseMode)
    {
    case 3:
        muxclientTunnelUpStreamResume(pqFixture->mux, pqFixture->child_l);
        break;
    case 4:
        muxclientTunnelUpStreamPause(pqFixture->mux, pqFixture->child_l);
        break;
    case 5:
        muxclientTunnelUpStreamFinish(pqFixture->mux, pqFixture->child_l);
        lineDestroy(pqFixture->child_l);
        break;
    case 6:
        muxclientHandleParentLoss(pqFixture->mux, pqFixture->parent_l, true);
        break;
    }
}

static void caseClientPauseBeforeOpen(unsigned representation, unsigned mode)
{
    twfSetCase("MuxClient reconciles pre-Open Pause across ordinary/splice submission and reentrant callbacks");
    pq_fixture_t f;
    pqSetup(&f);
#if WW_HAVE_SPLICE
    if (representation == 2 && ! pqHaveMaximumPipe(&f))
    {
        fixtureTeardown(&f);
        return;
    }
#endif
    const uint32_t length           = representation == 2 ? kMuxMaxDataFrameLength + 3U : 17U;
    f.capture                       = memoryReAllocate(f.capture, length + 128U);
    f.trace.capture                 = f.capture;
    f.trace.capture_capacity        = length + 128U;
    pqParentSink(&f)->pqPayloadSlot = pqOpeningPauseSink;
    pqOpeningPauseMode              = mode;
    pq_state_t *child               = lineGetState(f.child_l, f.mux);
    muxclientTunnelUpStreamPause(f.mux, f.child_l);
    twfRequire(child->paused && ! child->flow_paused_sent && pqDeliveries == 0,
               "child emitted FlowPause before its Open");
    if (mode == 1)
        pqParentPause(&f);
    if (mode == 2)
        muxclientTunnelUpStreamResume(f.mux, f.child_l);
    lineRef(f.parent_l);
    lineRef(f.child_l);
    sbuf_t *input;
#if WW_HAVE_SPLICE
    if (representation == 2)
    {
        pqBatchLength = length;
        input         = pqLargeSplice(&f);
    }
    else if (representation == 1)
        input = pqSplicePattern(&f, length);
    else
#endif
        input = makePatternPayload(&f, length);
    pqSend(f.mux, f.child_l, input);
    const bool expect_pause = mode == 0 || mode == 1 || mode == 4;
    if (mode == 1)
    {
        twfRequire(pqDeliveries == 0 && child->flow_paused_sent,
                   "paused parent did not retain the pre-Open FlowPause after Open/Data");
        pqParentResume(&f);
    }
    frame_view_t   frames[8];
    unsigned       count       = parseFrames(f.capture, f.trace.capture_len, frames, ARRAY_SIZE(frames));
    const unsigned data_frames = representation == 2 && mode != 6 ? 2U : 1U;
    twfRequire(count == 1U + data_frames + expect_pause + (mode == 5) && frames[0].flags == kMuxFlagOpen,
               "pre-Open Pause lost, duplicated, or reordered a control frame");
    uint32_t offset = 0;
    for (unsigned i = 1; i <= data_frames; ++i)
    {
        twfRequire(frames[i].flags == kMuxFlagData && frames[i].cid == kTestChildCid,
                   "pre-Open FlowPause overtook admitted Data");
        for (uint32_t j = 0; j < frames[i].length; ++j)
            twfRequire(frames[i].data[j] == patternByte(offset++), "pre-Open Pause changed payload bytes");
    }
    if (mode != 6)
        twfRequire(offset == length, "pre-Open Pause lost admitted payload");
    if (expect_pause)
    {
        twfRequire(frames[count - 1].flags == kMuxFlagFlowPause && child->flow_paused_sent,
                   "paused child did not signal the peer immediately after Open/Data");
        muxclientTunnelUpStreamResume(f.mux, f.child_l);
        twfRequire(! child->flow_paused_sent, "resumed child retained its sent-pause latch");
        count = parseFrames(f.capture, f.trace.capture_len, frames, ARRAY_SIZE(frames));
        twfRequire(count == data_frames + 3U && frames[count - 1].flags == kMuxFlagFlowResume,
                   "pre-Open Pause did not receive its matching FlowResume");
    }
    if (mode == 5)
        twfRequire(! lineIsAlive(f.child_l) && frames[count - 1].flags == kMuxFlagClose,
                   "reentrant child close emitted a late FlowPause");
    if (mode == 6)
        twfRequire(! lineIsAlive(f.parent_l), "reentrant parent loss left its owned line alive");
    const bool parent_dead = ! lineIsAlive(f.parent_l);
    const bool child_dead  = ! lineIsAlive(f.child_l);
    lineUnref(f.parent_l);
    lineUnref(f.child_l);
    if (parent_dead)
        f.parent_l = NULL;
    if (child_dead)
        f.child_l = NULL;
    fixtureTeardown(&f);
}
#endif

/* Boundary inputs use low-profile receive geometry and independent wire bytes. */
static void pqReceiveBytes(pq_fixture_t *f, const uint8_t *bytes, uint32_t length)
{
    sbuf_t *input = bufferpoolGetBestFit(f->env.pool, length, bufferpoolGetLargeBufferPadding(f->env.pool));
    memoryCopy(sbufGetMutablePtr(input), bytes, length);
    sbufSetLength(input, length);
    pqReceive(f->mux, f->parent_l, input);
}

static void caseFrameLengthFragmentation(uint32_t length, uint32_t first, bool byte_tail)
{
    twfSetCase("24-bit frame waits for its exact body including header accounting on low-profile pools");
    g_pool_size = LARGE_BUFFER_SIZE_RAM_LOW;
    pq_fixture_t f;
    fixtureSetup(&f, length + 1U);
    const uint32_t wire_length = kMuxFrameLength + length;
    uint8_t       *wire        = memoryAllocate(wire_length);
    writeFrameHeader(wire, length, kMuxFlagData, kTestChildCid);
    for (uint32_t i = 0; i < length; ++i)
        wire[kMuxFrameLength + i] = patternByte(i);
    pqReceiveBytes(&f, wire, first);
    pq_state_t *parent = lineGetState(f.parent_l, f.mux);
    twfRequire(lineIsAlive(f.parent_l) && parent->parent_state != NULL && pqChildDeliveries(&f) == 0,
               "valid incomplete maximum frame closed or delivered early");
    for (uint32_t offset = first; offset < wire_length;)
    {
        const uint32_t count = byte_tail ? 1U : wire_length - offset;
        pqReceiveBytes(&f, wire + offset, count);
        offset += count;
        if (offset < wire_length)
            twfRequire(parent->parent_state != NULL && pqChildDeliveries(&f) == 0 &&
                           splicestreamLength(parent->parent_state->read_stream) == offset,
                       "header bytes incorrectly triggered incomplete-frame overflow");
    }
    twfRequire(pqChildDeliveries(&f) == 1 && f.trace.capture_len == length &&
                   splicestreamLength(parent->parent_state->read_stream) == 0,
               "completed boundary frame was not delivered exactly once");
    for (uint32_t i = 0; i < length; ++i)
        twfRequire(f.capture[i] == patternByte(i), "fragmented maximum body changed bytes");
    memoryFree(wire);
    fixtureTeardown(&f);
    g_pool_size = kTestLargeBufferSize;
}

static void caseInvalidFrameLength(uint32_t length, uint8_t flag, bool unknown_cid, bool suffix)
{
    twfSetCase("oversized declaration closes only its parent at header completion and discards suffix");
    pq_fixture_t f;
    fixtureSetup(&f, 64);
    pq_tstate_t *ts = tunnelGetState(f.mux);
    discard      ts;
    /* A second independent parent must remain usable after malformed input. */
    line_t     *other_parent = twfLinePoolCreateLine(&f.lines);
    pq_state_t *other        = lineGetState(other_parent, f.mux);
#ifdef MUX_OUTPUT_CLIENT
    muxclientLinestateInitialize(f.mux, other, other_parent, false, 0);
    muxclientRegisterParent(ts, other);
#else
    muxserverLinestateInitialize(f.mux, other, other_parent, false, 0);
#endif
    line_t *other_child                                       = pqSibling(&f, other, 99);
    ((pq_state_t *) lineGetState(other_child, f.mux))->paused = false;
    uint8_t wire[2 * kMuxFrameLength + 1];
    writeFrameHeader(wire, length, flag, unknown_cid ? UINT32_MAX : kTestChildCid);
    writeFrameHeader(wire + kMuxFrameLength, 1, kMuxFlagData, kTestChildCid);
    wire[2 * kMuxFrameLength] = 0x5a;
    lineRef(f.parent_l);
    lineRef(f.child_l);
    pqReceiveBytes(&f, wire, 7);
    twfRequire(((pq_state_t *) lineGetState(f.parent_l, f.mux))->parent_state != NULL,
               "partial malformed header closed before length could be decoded");
#if WW_HAVE_SPLICE
    if (suffix)
        pqReceive(f.mux, f.parent_l, pqSpliceBytes(&f, wire + 7, sizeof(wire) - 7U));
    else
#endif
        pqReceiveBytes(&f, wire + 7, suffix ? sizeof(wire) - 7U : 1U);
    twfRequire(pqChildDeliveries(&f) == 0, "invalid frame or suffix reached a child");
    twfRequireLineStateZeroed(f.parent_l, f.mux, "invalid length retained parent state");

#ifdef MUX_OUTPUT_CLIENT
    twfRequire(! lineIsAlive(f.parent_l) && f.trace.next_finish == 1, "invalid length did not destroy owned parent");
    lineUnref(f.parent_l);
    f.parent_l = NULL;
    lineUnref(f.child_l);
#else
    twfRequire(f.trace.prev_finish == 1 && ! lineIsAlive(f.child_l), "invalid length did not close borrowed parent");
    lineUnref(f.parent_l);
    lineUnref(f.child_l);
    f.child_l = NULL;
#endif
    line_t *saved_parent = f.parent_l;
    f.parent_l           = other_parent;
    writeFrameHeader(wire, 1, kMuxFlagData, 99);
    wire[kMuxFrameLength] = 0x36;
    pqReceiveBytes(&f, wire, kMuxFrameLength + 1);
    twfRequire(pqChildDeliveries(&f) == 1 && f.capture[0] == 0x36, "malformed peer damaged independent parent");
    pqDestroySibling(&f, other_child);
#ifdef MUX_OUTPUT_CLIENT
    muxclientUnregisterParent(ts, other);
    muxclientLinestateDestroy(other);
#else
    muxserverLinestateDestroy(f.mux, other);
#endif
    lineDestroy(other_parent);
    f.parent_l = saved_parent;
    fixtureTeardown(&f);
}

static void runFrameLengthCases(void)
{
    const uint32_t lengths[] = {0, 1, 65527, 65535, 65536, kMuxMaxDataFrameLength - 1, kMuxMaxDataFrameLength};
    for (size_t i = 0; i < ARRAY_SIZE(lengths); ++i)
        for (uint32_t split = 1; split < kMuxFrameLength; ++split)
            caseFrameLengthFragmentation(lengths[i], split, false);
    caseFrameLengthFragmentation(kMuxMaxDataFrameLength, 65535, false);
    caseFrameLengthFragmentation(kMuxMaxDataFrameLength, 65536, false);
    caseFrameLengthFragmentation(kMuxMaxDataFrameLength, kMuxMaxBufferedFrameLength - 1U, false);
    caseFrameLengthFragmentation(kMuxMaxDataFrameLength, kMuxMaxDataFrameLength, true);
    const uint8_t flags[] = {kMuxFlagOpen, kMuxFlagClose, kMuxFlagFlowPause, kMuxFlagFlowResume, kMuxFlagData, 255};
    for (size_t i = 0; i < ARRAY_SIZE(flags); ++i)
        for (unsigned cid = 0; cid < 2; ++cid)
            for (unsigned suffix = 0; suffix < 2; ++suffix)
            {
                caseInvalidFrameLength(kMuxMaxDataFrameLength + 1U, flags[i], cid != 0, suffix != 0);
                caseInvalidFrameLength(0xffffff, flags[i], cid != 0, suffix != 0);
            }
}

#include "mux_receive_limits_cases.h"

static void runParentOutputCases(void)
{
    caseChildPauseWithoutQueuedData();
#ifdef MUX_OUTPUT_CLIENT
    for (unsigned mode = 0; mode < 7; ++mode)
    {
        caseClientPauseBeforeOpen(0, mode);
#if WW_HAVE_SPLICE
        caseClientPauseBeforeOpen(1, mode);
        caseClientPauseBeforeOpen(2, mode);
#endif
    }
#endif
    caseParentEarlyRelease();
    caseParentResumeBoundary(0);
    caseParentResumeBoundary(2);
    caseParentResumeFIFO();
    caseParentFairness();
    caseParentThrottleClock();
    for (unsigned mode = 0; mode < 5; ++mode)
        caseParentResumeMutation(mode);
    runReceiveLimitCases();
    runFrameLengthCases();
#if WW_HAVE_SPLICE
    caseMaximumFittingSplice();
    for (unsigned mode = 0; mode < 6; ++mode)
        caseSpliceBatch(mode);
    for (unsigned mode = 0; mode < 4; ++mode)
        caseSpliceBatchAdmission(mode);
    runBoundedSpliceRetentionCases();
    for (unsigned detach = 0; detach < 3; ++detach)
        for (unsigned discard_queue = 0; discard_queue < 2; ++discard_queue)
            caseAccountedSpliceLifecycle(detach, discard_queue != 0);
    caseAccountedSpliceReservationFailure();
    for (unsigned input = 0; input < 2; ++input)
        for (unsigned complete = 0; complete < 2; ++complete)
            for (unsigned paused = 0; paused < 2; ++paused)
                caseSpliceManyIncompleteFragments(input != 0, complete != 0, paused != 0);
    caseSpliceParentOutput(false);
    caseSpliceParentOutput(true);
    caseSpliceParentRefusal();
    caseSpliceIncompleteCarrier();
    for (unsigned paused = 0; paused < 2; ++paused)
        for (unsigned in_pipe = 0; in_pipe < 2; ++in_pipe)
        {
            caseSpliceDecodedFrames(paused != 0, in_pipe != 0, 0);
            caseSpliceDecodedFrames(paused != 0, in_pipe != 0, 32);
        }
#endif
    caseChildCloseKeepsParentParsing();
    caseQueueLimitCloseCannotReenterChild();
    caseParentQueuedChildClose(false);
    caseParentQueuedChildClose(true);
    caseParentAdmissionArithmeticAndDirect();
    caseParentPumpReentrancy();
    caseParentGate(2000, false);
    caseParentGate(3, true);
    caseParentGateMutation();
    caseParentHardLimit(true, false, false);
    caseParentHardLimit(false, false, false);
    caseParentHardLimit(true, true, false);
    caseParentHardLimit(false, false, true);
    caseParentWriteConfiguration();
    caseParentResumeConfiguration();
}
