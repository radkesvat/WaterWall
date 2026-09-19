/* Shared real-callback coverage for bounded complete-frame pipe retention. */
#pragma once

#if WW_HAVE_SPLICE
static line_t  *pqRetentionSibling;
static uint32_t pqRetentionChildDeliveries;

static void pqCheckQueueCharges(void)
{
    pq_fixture_t   *f          = pqFixture;
    pq_state_t     *parent     = lineGetState(f->parent_l, f->mux);
    pq_state_t     *child      = lineGetState(f->child_l, f->mux);
    pq_state_t     *sibling    = lineGetState(pqRetentionSibling, f->mux);
    buffer_queue_t *queues[]   = {&child->pending_child_data, &sibling->pending_child_data, &pqOutput(f)->pending};
    size_t          charges[3] = {0};
    for (unsigned i = 0; i < ARRAY_SIZE(queues); ++i)
        c_foreach(entry, ww_sbuffer_queue_t, queues[i]->q) charges[i] += sbufGetQueueCharge(*entry.ref);
    twfRequire(child->pending_child_queue_charge == charges[0] && sibling->pending_child_queue_charge == charges[1] &&
                   parent->pending_child_queue_charge == charges[0] + charges[1] && pqOutput(f)->charge == charges[2],
               "local queue capacity charges disagree with ownership");
}

static void pqRetentionChildSink(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    pqCheckQueueCharges();
    buf = muxMaterializeRetainedPayload(lineGetBufferPool(l), buf);
    twfRequire(sbufGetLength(buf) == 1 && *(const uint8_t *) sbufGetRawPtr(buf) == patternByte(0),
               "retained child delivery lost its frame bytes");
    ++pqRetentionChildDeliveries;
    lineReuseBuffer(l, buf);
}

static void pqRetentionParentSink(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pqCheckQueueCharges();
    buf = muxMaterializeRetainedPayload(lineGetBufferPool(l), buf);
    pqSink(t, l, buf);
}

static void caseIndependentSpliceRetention(void)
{
    twfSetCase("more than 64 pipes and 8 MiB nominal capacity remain retained under local budgets");
    pq_fixture_t f;
    pqSetup(&f);
    pqSetSpliceSinks(&f);
    pq_tstate_t *ts                 = tunnelGetState(f.mux);
    pq_state_t  *parent             = lineGetState(f.parent_l, f.mux);
    pq_state_t  *child              = lineGetState(f.child_l, f.mux);
    child->paused                   = true;
    pqRetentionSibling              = pqSibling(&f, parent, 100);
    pq_state_t *sibling             = lineGetState(pqRetentionSibling, f.mux);
    sibling->paused                 = true;
    pqRetentionChildDeliveries      = 0;
    pqParentSink(&f)->pqPayloadSlot = pqRetentionParentSink;
#ifdef MUX_OUTPUT_CLIENT
    f.prev->fnPayloadD = pqRetentionChildSink;
#else
    f.next->fnPayloadU = pqRetentionChildSink;
#endif
    pqParentPause(&f);
    size_t   kernel_capacity = 0;
    unsigned children        = 0;
    for (unsigned i = 0; i < 144; ++i)
    {
        sbuf_t *input = pqSplicePattern(&f, 1);
        kernel_capacity += sbufSpliceMetadata(input).pipe_capacity;
        buffer_queue_t *queue;
        if (i % 3 == 0)
        {
            queue = &pqOutput(&f)->pending;
            pqSend(f.mux, f.child_l, input);
        }
        else
        {
            pq_state_t *target = i % 3 == 1 ? child : sibling;
            queue              = &target->pending_child_data;
            twfRequire(pqQueue(f.mux, f.parent_l, ts, parent, target, input), "local admission refused");
            ++children;
        }
        twfRequire(*ww_sbuffer_queue_t_back(&queue->q) == input && sbufIsSplice(input) && pqMaterializedBodyBytes == 0,
                   "other retained pipes forced ordinary conversion");
        pqCheckQueueCharges();
    }
    if (kernel_capacity <= 8U * 1024U * 1024U)
        fprintf(stderr,
                "SKIP: host granted only %zu bytes nominal pipe capacity; >8 MiB coverage unavailable\n",
                kernel_capacity);
    pqParentResume(&f);
    pqResumeDecodedChild(&f);
#ifdef MUX_OUTPUT_CLIENT
    muxclientTunnelUpStreamResume(f.mux, pqRetentionSibling);
#else
    muxserverTunnelDownStreamResume(f.mux, pqRetentionSibling);
#endif
    twfRequire(pqRetentionChildDeliveries == children && pqOutput(&f)->charge == 0,
               "independent retention drain lost data");
    pqCheckQueueCharges();
    pqDestroySibling(&f, pqRetentionSibling);
    pqRetentionSibling = NULL;
    fixtureTeardown(&f);
}

static void pqSettledParentSink(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    size_t charge = 0;
    c_foreach(entry, ww_sbuffer_queue_t, pqOutput(pqFixture)->pending.q) charge += sbufGetQueueCharge(*entry.ref);
    twfRequire(charge == pqOutput(pqFixture)->charge, "pop did not settle output charge before callback");
    pqSpliceParentSink(t, l, buf);
}

static void caseQueuedSpliceOutlivesChild(void)
{
    twfSetCase("closing the producer does not release its parent's queued capacity charge");
    pq_fixture_t f;
    pqSetup(&f);
    pqSetSpliceSinks(&f);
    pqParentSink(&f)->pqPayloadSlot = pqSettledParentSink;
    pqParentPause(&f);

    sbuf_t *input     = pqSplicePattern(&f, 32);
    pqExpectedPipe    = sbufSpliceMetadata(input).pipefd[0];
    const size_t cost = sbufGetQueueCharge(input);
    pqSend(f.mux, f.child_l, input);
    lineRef(f.child_l);
    pqFinish(f.mux, f.child_l);
    twfRequireLineStateZeroed(f.child_l, f.mux, "producer Finish retained its child state");
    twfRequire(pqOutput(&f)->charge >= cost && pqMaterializedBodyBytes == 0 && pqDeliveries == 0,
               "child close released parent-owned queue charge or consumed queued output");
#ifndef MUX_OUTPUT_CLIENT
    twfRequire(! lineIsAlive(f.child_l), "server Finish left an owned child alive");
#endif
    lineUnref(f.child_l);
#ifndef MUX_OUTPUT_CLIENT
    f.child_l = NULL;
#endif
    pqParentResume(&f);
    twfRequire(pqSpliceParentDeliveries == 1 && pqOutput(&f)->charge == 0,
               "parent backlog failed to settle after its originating child closed");
    frame_view_t   frames[3];
    const unsigned n = parseFrames(f.capture, f.trace.capture_len, frames, ARRAY_SIZE(frames));
    twfRequire(n == 2 && frames[0].flags == kMuxFlagData && frames[0].length == 32 && frames[1].flags == kMuxFlagClose,
               "child close reordered the parent's queued Data and Close");
    fixtureTeardown(&f);
}

static void caseQueuedSpliceNestedOutput(void)
{
    twfSetCase("queued pipe Resume settles charge before nested output and synchronous Pause+Resume");
    pq_fixture_t f;
    pqSetup(&f);
    pqSetSpliceSinks(&f);
    pqParentSink(&f)->pqPayloadSlot = pqSettledParentSink;
    pqParentPause(&f);
    sbuf_t *input  = pqSplicePattern(&f, 32);
    pqExpectedPipe = sbufSpliceMetadata(input).pipefd[0];
    pqSend(f.mux, f.child_l, input);
    twfRequire(pqMaterializedBodyBytes == 0, "queued reentrancy fixture materialized its body early");
    pqNestedAt = pqToggleAt = 1;
    pqParentResume(&f);
    twfRequire(pqDeliveries == 2 && pqSpliceParentDeliveries == 1 && pqOutput(&f)->charge == 0,
               "reentrant queued output stranded a buffer or leaked queue charge");
    frame_view_t   frames[3];
    const unsigned n = parseFrames(f.capture, f.trace.capture_len, frames, ARRAY_SIZE(frames));
    twfRequire(n == 2 && frames[0].length == 32 && frames[1].length == 4,
               "nested output overtook the original queued frame");
    fixtureTeardown(&f);
}

static void pqFinishOnPipeDelivery(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pqAccountingChildSink(t, l, buf);
    pqFinish(pqFixture->mux, l);
#ifdef MUX_OUTPUT_CLIENT
    lineDestroy(l); // The fake previous source owns the borrowed client child.
#endif
}

static void caseQueuedSpliceChildDiesOnDelivery(void)
{
    twfSetCase("a child may die on pipe delivery after its queue charge is released");
    pq_fixture_t f;
    pqSetup(&f);
    pqSetSpliceSinks(&f);
    pq_tstate_t *ts      = tunnelGetState(f.mux);
    pq_state_t  *parent  = lineGetState(f.parent_l, f.mux);
    pq_state_t  *child   = lineGetState(f.child_l, f.mux);
    line_t      *sibling = pqSibling(&f, parent, 100);
    child->paused        = true;

    sbuf_t *input         = pqSplicePattern(&f, 32);
    pqExpectedPipe        = sbufSpliceMetadata(input).pipefd[0];
    pqExpectedChildLength = 32;
    pqExpectSpliceChild   = true;
    twfRequire(pqQueue(f.mux, f.parent_l, ts, parent, child, input), "failed to queue child-death fixture");
#ifdef MUX_OUTPUT_CLIENT
    f.prev->fnPayloadD = pqFinishOnPipeDelivery;
#else
    f.next->fnPayloadU = pqFinishOnPipeDelivery;
#endif
    lineRef(f.child_l);
    pqResumeDecodedChild(&f);
    twfRequire(! lineIsAlive(f.child_l) && lineIsAlive(f.parent_l) && lineIsAlive(sibling) &&
                   pqSpliceChildDeliveries == 1,
               "reentrant child close leaked cost or killed an unrelated line");
    lineUnref(f.child_l);
    f.child_l = sibling;
    fixtureTeardown(&f);
}

static void caseSpliceLocalLimit(bool parent_output, bool refuse_entry)
{
    twfSetCase("local queue budgets preserve splice representation and equality/refusal rules");
    pq_fixture_t f;
    pqSetup(&f);
    pqSetSpliceSinks(&f);
    pq_tstate_t *ts     = tunnelGetState(f.mux);
    pq_state_t  *parent = lineGetState(f.parent_l, f.mux);
    pq_state_t  *child  = lineGetState(f.child_l, f.mux);

    sbuf_t      *input        = pqSplicePattern(&f, 32);
    const size_t entry_charge = sbufGetQueueCharge(input);
    pqExpectedPipe            = sbufSpliceMetadata(input).pipefd[0];
    pqExpectedChildLength     = 32;
    pqExpectSpliceChild       = true;
    if (parent_output)
    {
        ts->parent_write_limit           = (uint32_t) (entry_charge - (refuse_entry ? 1U : 0U));
        ts->parent_write_pause_threshold = 1;
        pqParentPause(&f);
    }
    else
    {
        child->paused          = true;
        ts->child_buffer_limit = (uint32_t) (entry_charge + (refuse_entry ? 0U : 1U));
    }
    lineRef(f.parent_l);
    lineRef(f.child_l);
    if (parent_output)
        pqSend(f.mux, f.child_l, input);
    else
        discard pqQueue(f.mux, f.parent_l, ts, parent, child, input);
    twfRequire(pqMaterializedBodyBytes == 0, "local queue limit materialized a valid splice body");
    if (refuse_entry)
    {
        twfRequireLineStateZeroed(f.child_l, f.mux, "local refusal left child state retained");
        if (parent_output)
            twfRequireLineStateZeroed(f.parent_l, f.mux, "output refusal left parent state retained");
        else
            twfRequire(lineIsAlive(f.parent_l) && parent->parent_state != NULL,
                       "child equality refusal closed the unrelated carrier");
        twfRequire(pqSpliceChildDeliveries == 0, "local refusal delivered an unadmitted child payload");
    }
    else
    {
        buffer_queue_t *queue  = parent_output ? &pqOutput(&f)->pending : &child->pending_child_data;
        const sbuf_t   *queued = bufferqueueFront(queue);
        twfRequire(queued != NULL && sbufIsSplice(queued) && sbufGetQueueCharge(queued) == entry_charge,
                   "splice storage was not charged at its actual logical capacity");
        if (parent_output)
        {
            twfRequire(pqOutput(&f)->charge == ts->parent_write_limit,
                       "parent output did not admit equality for retained splice output");
            pqParentResume(&f);
            frame_view_t   frames[2];
            const unsigned count = parseFrames(f.capture, f.trace.capture_len, frames, ARRAY_SIZE(frames));
            twfRequire(count == 1 && frames[0].flags == kMuxFlagData && frames[0].length == 32,
                       "splice output changed exact frame boundaries");
            for (uint32_t i = 0; i < 32; ++i)
                twfRequire(frames[0].data[i] == patternByte(i), "splice output changed payload bytes");
        }
        else
        {
            twfRequire(child->pending_child_queue_charge + 1 == ts->child_buffer_limit,
                       "splice child did not preserve its strict below-limit comparison");
            pqResumeDecodedChild(&f);
            twfRequire(pqSpliceChildDeliveries == 1, "splice child did not Resume exactly once");
        }
    }
    const bool parent_dead = ! lineIsAlive(f.parent_l);
    const bool child_dead  = ! lineIsAlive(f.child_l);
    lineUnref(f.child_l);
    lineUnref(f.parent_l);
    if (child_dead)
        f.child_l = NULL;
    if (parent_dead)
        f.parent_l = NULL;
    fixtureTeardown(&f);
}

static void runBoundedSpliceRetentionCases(void)
{
    for (unsigned output = 0; output < 2; ++output)
        for (unsigned refusal = 0; refusal < 2; ++refusal)
            caseSpliceLocalLimit(output != 0, refusal != 0);
    caseIndependentSpliceRetention();
    caseQueuedSpliceOutlivesChild();
    caseQueuedSpliceNestedOutput();
    caseQueuedSpliceChildDiesOnDelivery();
}
#endif
