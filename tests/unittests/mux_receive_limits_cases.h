/* Included by both Mux fixtures; all inputs use the real parser and queue helpers. */
#pragma once

#ifdef MUX_OUTPUT_CLIENT
#define pqEnforce muxclientEnforceParentReceiveLimit
#else
#define pqEnforce muxserverEnforceParentReceiveLimit
#endif

static void pqReleaseClosedFixtureRefs(pq_fixture_t *f)
{
    bool parent_dead = ! lineIsAlive(f->parent_l);
    bool child_dead  = ! lineIsAlive(f->child_l);
    lineUnref(f->parent_l);
    lineUnref(f->child_l);
    if (parent_dead)
        f->parent_l = NULL;
    if (child_dead)
        f->child_l = NULL;
}

static void caseIncomingReceiveLimit(bool unlimited, bool partial_header)
{
    twfSetCase("incoming-only retention respects parent equality, including partial headers and unlimited mode");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts         = tunnelGetState(f.mux);
    sbuf_t      *input      = bufferpoolGetSmallBuffer(f.env.pool);
    const size_t charge     = sbufGetQueueCharge(input);
    ts->parent_buffer_limit = unlimited ? 0 : (uint32_t) charge;
    if (partial_header)
    {
        /* A short header is cached, so it owns no sbuf charge after consumption. */
        sbufSetLength(input, 7);
        writeFrameHeader(sbufGetMutablePtr(input), 100, kMuxFlagData, kTestChildCid);
    }
    else
    {
        sbufSetLength(input, kMuxFrameLength + 1);
        writeFrameHeader(sbufGetMutablePtr(input), 100, kMuxFlagData, kTestChildCid);
        sbufGetMutablePtr(input)[kMuxFrameLength] = 17;
    }
    lineRef(f.parent_l);
    lineRef(f.child_l);
    pqReceive(f.mux, f.parent_l, input);
    pq_state_t *parent = lineGetState(f.parent_l, f.mux);
    if (unlimited || partial_header)
    {
        twfRequire(parent->parent_state != NULL && parent->pending_child_queue_charge == 0,
                   "incoming accounting leaked into child aggregate or imposed an implicit cap");
        twfRequire(splicestreamCharge(parent->parent_state->read_stream) == (partial_header ? 0 : charge),
                   "cached header charged an exhausted sbuf or incomplete body was uncharged");
    }
    else
        twfRequireLineStateZeroed(f.parent_l, f.mux, "incoming-only equality left parent over limit");
    pqReleaseClosedFixtureRefs(&f);
    fixtureTeardown(&f);
}

#if WW_HAVE_SPLICE
static void caseReceiveCompaction(bool beneficial)
{
    twfSetCase("receive pressure compacts only for a strict saving and preserves cached header/body");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts     = tunnelGetState(f.mux);
    pq_state_t  *parent = lineGetState(f.parent_l, f.mux);
    uint8_t      header[kMuxFrameLength];
    writeFrameHeader(header, beneficial ? 100 : 10, kMuxFlagData, kTestChildCid);
    pqReceiveBytes(&f, header, sizeof(header));
    const size_t one = sizeof(sbuf_t) + bufferpoolGetSpliceBufferPadding(f.env.pool) + 1 + kSbufAllocationAlignment;
    buffer_pool_fit_t fit;
    twfRequire(bufferpoolQueryBestFit(f.env.pool, 100, bufferpoolGetLargeBufferPadding(f.env.pool), &fit),
               "bad compaction geometry");
    ts->parent_buffer_limit = beneficial ? (uint32_t) fit.allocation_charge + 1U : (uint32_t) one;
    lineRef(f.parent_l);
    lineRef(f.child_l);
    pqMaterializedBodyBytes = 0;
    for (uint32_t i = 0; i < (beneficial ? 99U : 1U); ++i)
        pqReceive(f.mux, f.parent_l, pqTinyCarrierByte(&f, i, true));
    if (beneficial)
    {
        twfRequire(parent->parent_state != NULL && pqMaterializedBodyBytes > 0 &&
                       splicestreamLength(parent->parent_state->read_stream) == 107 &&
                       splicestreamCharge(parent->parent_state->read_stream) < ts->parent_buffer_limit &&
                       memcmp(splicestreamPeekHeader(parent->parent_state->read_stream), header, 8) == 0,
                   "beneficial pressure compaction lost bytes, header, or charge bound");
        const uint8_t last = patternByte(99);
        pqReceiveBytes(&f, &last, 1);
        twfRequire(pqChildDeliveries(&f) == 1 && f.trace.capture_len == 100, "compacted frame did not finish once");
        for (unsigned i = 0; i < 100; ++i)
            twfRequire(f.capture[i] == patternByte(i), "compacted frame changed byte order");
    }
    else
    {
        twfRequireLineStateZeroed(f.parent_l, f.mux, "non-beneficial compaction failed to close over-limit parent");
        twfRequire(pqMaterializedBodyBytes == 0, "non-beneficial pressure converted pipe before rejecting");
    }
    pqReleaseClosedFixtureRefs(&f);
    fixtureTeardown(&f);
}
#endif

static pq_fixture_t *receivePressureFixture;
static void          pqDieDuringPressureClose(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    pqLoss(receivePressureFixture->mux, receivePressureFixture->parent_l, true);
}

static void caseReceiveMultipleVictims(bool kill_parent)
{
    twfSetCase("combined receive pressure sheds multiple largest children with oldest ties and handles parent death");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts          = tunnelGetState(f.mux);
    pq_state_t  *parent      = lineGetState(f.parent_l, f.mux);
    line_t      *children[3] = {f.child_l, pqSibling(&f, parent, 20), pqSibling(&f, parent, 21)};
    ts->parent_buffer_limit  = 0;
    size_t charge            = 0;
    for (unsigned i = 0; i < 3; ++i)
    {
        lineRef(children[i]);
        pq_state_t *child = lineGetState(children[i], f.mux);
        child->paused     = true;
#ifdef MUX_OUTPUT_CLIENT
        child->open_frame_submitted = true;
#endif
        twfRequire(pqQueue(f.mux, f.parent_l, ts, parent, child, makePatternPayload(&f, 1)), "cannot seed child queue");
        charge = child->pending_child_queue_charge;
    }
    uint8_t header[9];
    writeFrameHeader(header, 100, kMuxFlagData, kTestChildCid);
    header[8] = 17;
    pqReceiveBytes(&f, header, sizeof(header));
    const size_t incoming   = splicestreamCharge(parent->parent_state->read_stream);
    ts->parent_buffer_limit = (uint32_t) (incoming + charge + 1);
    if (kill_parent)
    {
        receivePressureFixture = &f;
#ifdef MUX_OUTPUT_CLIENT
        f.prev->fnFinD = pqDieDuringPressureClose;
#else
        f.next->fnFinU = pqDieDuringPressureClose;
#endif
    }
    lineRef(f.parent_l);
    const bool alive = pqEnforce(f.mux, f.parent_l);
    if (! kill_parent)
    {
        twfRequire(alive && parent->children_count == 1 &&
                       ((pq_state_t *) lineGetState(children[2], f.mux))->parent == parent,
                   "pressure failed to remove two oldest equal-charge victims");
        twfRequireLineStateZeroed(children[0], f.mux, "oldest victim retained state");
        twfRequireLineStateZeroed(children[1], f.mux, "second victim retained state");
        twfRequire(parent->pending_child_queue_charge == charge &&
                       splicestreamCharge(parent->parent_state->read_stream) == incoming,
                   "shedding mixed child and incoming ownership counters");
    }
    else
        twfRequire(! alive, "parent death during victim Close was ignored");
    bool parent_dead = ! lineIsAlive(f.parent_l);
    lineUnref(f.parent_l);
    if (parent_dead)
        f.parent_l = NULL;
    /* Settle surviving queues through the normal parent loss/drain paths. */
    if (! kill_parent)
        pqDestroySibling(&f, children[2]);
    else
    {
#ifdef MUX_OUTPUT_CLIENT
        f.prev->fnFinD = twfPrevFinish;
#else
        f.next->fnFinU = twfNextFinish;
#endif
        for (unsigned i = 1; i < 3; ++i)
        {
            pq_state_t *child = lineGetState(children[i], f.mux);
            if (child->l != NULL)
                pqFinish(f.mux, children[i]);
        }
    }
    for (unsigned i = 0; i < 3; ++i)
    {
        bool dead = ! lineIsAlive(children[i]);
        lineUnref(children[i]);
        if (i == 0 && dead)
            f.child_l = NULL;
#ifdef MUX_OUTPUT_CLIENT
        if (i != 0 && ! dead)
            lineDestroy(children[i]);
#endif
    }
    fixtureTeardown(&f);
}

#if WW_HAVE_SPLICE
#include <dirent.h>

static size_t pqOpenDescriptorCount(void)
{
    DIR *directory = opendir("/proc/self/fd");
    twfRequire(directory != NULL, "cannot inspect high-child fixture descriptors");
    size_t         count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL)
        if (entry->d_name[0] != '.')
            ++count;
    closedir(directory);
    return count;
}

static void pqQuietBorrowedFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
}

static void pqQuietOwnerFinish(tunnel_t *t, line_t *l)
{
    discard t;
    lineDestroy(l);
}

static void caseThousandsOfChildren(void)
{
    twfSetCase("10000 children across four parents reserve no pipes and retain independently");
    pq_fixture_t f;
    pqSetup(&f);
    pq_tstate_t *ts          = tunnelGetState(f.mux);
    line_t      *parents[4]  = {f.parent_l};
    line_t     **children    = memoryAllocate(10000 * sizeof(*children));
    const size_t descriptors = pqOpenDescriptorCount();
    for (unsigned p = 0; p < 4; ++p)
    {
        if (p != 0)
        {
            parents[p]        = twfLinePoolCreateLine(&f.lines);
            pq_state_t *state = lineGetState(parents[p], f.mux);
#ifdef MUX_OUTPUT_CLIENT
            muxclientLinestateInitialize(f.mux, state, parents[p], false, 0);
            muxclientRegisterParent(ts, state);
#else
            muxserverLinestateInitialize(f.mux, state, parents[p], false, 0);
#endif
        }
        lineRef(parents[p]);
        pq_state_t *parent = lineGetState(parents[p], f.mux);
        for (unsigned c = 0; c < 2500; ++c)
        {
            line_t *child          = p == 0 && c == 0 ? f.child_l : pqSibling(&f, parent, 100 + c);
            children[p * 2500 + c] = child;
            lineRef(child);
            pq_state_t *state = lineGetState(child, f.mux);
            state->paused     = true;
#ifdef MUX_OUTPUT_CLIENT
            state->open_frame_submitted = true;
#endif
        }
        twfRequire(parent->children_count == 2500 && parent->pending_child_queue_charge == 0 &&
                       parent->parent_state->output.charge == 0 &&
                       splicestreamCharge(parent->parent_state->read_stream) == 0,
                   "idle children acquired queue charges");
    }
    twfRequire(pqOpenDescriptorCount() == descriptors, "open-child count reserved pipe descriptors");
    pqMaterializedBodyBytes = 0;
    for (unsigned p = 0; p < 4; ++p)
    {
        pq_state_t *parent = lineGetState(parents[p], f.mux);
        pq_state_t *child  = lineGetState(children[p * 2500], f.mux);
        pqPause(f.mux, parents[p]);
        for (unsigned i = 0; i < 40; ++i)
        {
            sbuf_t         *input = pqSplicePattern(&f, 1);
            buffer_queue_t *queue;
            if (p % 2 == 0)
            {
                queue = &child->pending_child_data;
                twfRequire(pqQueue(f.mux, parents[p], ts, parent, child, input), "high-child queue refused valid pipe");
            }
            else
            {
                queue = &parent->parent_state->output.pending;
                pqSend(f.mux, children[p * 2500], input);
            }
            twfRequire(*ww_sbuffer_queue_t_back(&queue->q) == input && sbufIsSplice(input),
                       "another parent's retention forced materialization");
        }
    }
    twfRequire(pqMaterializedBodyBytes == 0, "independent parent retention read body bytes");
    f.prev->fnFinD                 = pqQuietOwnerFinish;
    f.next->fnFinU                 = pqQuietBorrowedFinish;
    ts->worker_states[0].quiescing = true;
    for (unsigned p = 0; p < 4; ++p)
        pqLoss(f.mux, parents[p], true);
    for (unsigned c = 0; c < 10000; ++c)
    {
        twfRequire(! lineIsAlive(children[c]), "high-child shutdown retained an owned/source line");
        twfRequireLineStateZeroed(children[c], f.mux, "high-child cleanup retained state");
        lineUnref(children[c]);
    }
    for (unsigned p = 0; p < 4; ++p)
    {
        twfRequire(! lineIsAlive(parents[p]), "high-child parent shutdown left a live line");
        twfRequireLineStateZeroed(parents[p], f.mux, "high-child cleanup retained parent stream/output");
        lineUnref(parents[p]);
    }
    f.parent_l = f.child_l = NULL;
    memoryFree(children);
    fixtureTeardown(&f);
}
#endif

static void runReceiveLimitCases(void)
{
    caseIncomingReceiveLimit(false, false);
    caseIncomingReceiveLimit(true, false);
    caseIncomingReceiveLimit(false, true);
    caseReceiveMultipleVictims(false);
    caseReceiveMultipleVictims(true);
#if WW_HAVE_SPLICE
    caseThousandsOfChildren();
    caseReceiveCompaction(false);
    caseReceiveCompaction(true);
#endif
}
