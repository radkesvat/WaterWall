#if WW_HAVE_SPLICE
static uint32_t pqBatchLength;
static unsigned pqBatchAction;
static unsigned pqBatchSpliceFrames;

static void pqBatchSink(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    if (pqDeliveries == 0)
    {
        twfRequire(bufferqueueGetBufCount(&pqOutput(pqFixture)->pending) == 1,
                   "first batch callback preceded complete FIFO publication");
        /* A real prefix may force complete ordinary fallback after partial splice progress. */
    }
    if ((buf->flags & kSbufFlagSplice) != 0)
    {
        ++pqBatchSpliceFrames;
        buf = muxMaterializeRetainedPayload(lineGetBufferPool(l), buf);
    }
    pqSink(t, l, buf);
    if (pqDeliveries == 1 && pqBatchAction == 1)
        pqFinish(pqFixture->mux, pqFixture->child_l);
    if (pqDeliveries == 1 && pqBatchAction == 2)
        pqLoss(pqFixture->mux, pqFixture->parent_l, true);
}

static sbuf_t *pqLargeSplice(pq_fixture_t *f)
{
    uint8_t *bytes = memoryAllocate(pqBatchLength);
    for (uint32_t i = 0; i < pqBatchLength; ++i)
        bytes[i] = patternByte(i);
    const uint32_t resident = pqBatchLength - kMuxMaxDataFrameLength;
    twfRequire(resident <= 16, "batch prefix exceeds available headroom");
    sbuf_t *input = pqSpliceBytes(f, bytes + resident, pqBatchLength - resident);
    if (resident != 0)
    {
        sbufShiftLeft(input, resident);
        sbufWrite(input, bytes, resident);
    }
    memoryFree(bytes);
    return input;
}

static void caseSpliceBatch(unsigned mode)
{
    twfSetCase("large splice batch publishes atomically and preserves Pause/Close ordering");
    pq_fixture_t f;
    pqSetup(&f);
    if (! pqHaveMaximumPipe(&f))
    {
        fixtureTeardown(&f);
        return;
    }
    pqBatchLength                   = kMuxMaxDataFrameLength + 3U;
    f.capture                       = memoryReAllocate(f.capture, pqBatchLength + 256U);
    f.trace.capture                 = f.capture;
    f.trace.capture_capacity        = pqBatchLength + 256U;
    pqParentSink(&f)->pqPayloadSlot = pqBatchSink;
    pqBatchAction                   = mode == 3 ? 1U : mode == 4 ? 2U : 0U;
    pqBatchSpliceFrames             = 0;
    pqMaterializedBodyBytes         = 0;
    if (mode == 0)
        pqParentPause(&f);
    if (mode == 1)
        pqPauseAt = 1;
    if (mode == 2)
    {
        pqNestedAt = 1;
        pqToggleAt = 1;
    }
    lineRef(f.parent_l);
    lineRef(f.child_l);
    pqSend(f.mux, f.child_l, pqLargeSplice(&f));
    if (mode == 0)
        twfRequire(pqDeliveries == 0 && bufferqueueGetBufCount(&pqOutput(&f)->pending) == 2,
                   "paused batch was not fully retained");
    if (mode == 1)
        twfRequire(pqDeliveries == 1 && bufferqueueGetBufCount(&pqOutput(&f)->pending) == 1,
                   "Pause during first frame failed to preserve admitted remainder");
    if (mode <= 1)
        pqParentResume(&f);
    if (mode != 4)
    {
        frame_view_t   frames[8];
        const uint32_t count = parseFrames(f.capture, f.trace.capture_len, frames, 8);
#ifdef MUX_OUTPUT_CLIENT
        const uint32_t start = 1;
        twfRequire(frames[0].flags == kMuxFlagOpen, "batch did not emit Open first");
#else
        const uint32_t start = 0;
#endif
        twfRequire(count == start + 2U + (mode == 2 || mode == 3), "batch frame/control count changed");
        uint32_t offset = 0;
        for (unsigned i = 0; i < 2; ++i)
        {
            const frame_view_t *frame = &frames[start + i];
            twfRequire(frame->flags == kMuxFlagData && frame->cid == kTestChildCid,
                       "control/nested data overtook batch data");
            for (uint32_t j = 0; j < frame->length; ++j)
                twfRequire(frame->data[j] == patternByte(offset++), "split batch corrupted payload");
        }
        twfRequire(offset == pqBatchLength, "batch lost bytes");
        if (mode == 3)
            twfRequire(frames[count - 1].flags == kMuxFlagClose, "reentrant Close preceded admitted Data");
        twfRequire(pqOutput(&f)->charge == 0, "batch drain leaked cost");
    }
    else
        twfRequire(pqDeliveries == 1, "parent death delivered or retained residual batch");
#ifdef MUX_OUTPUT_CLIENT
    const bool parent_dead = ! lineIsAlive(f.parent_l);
    lineUnref(f.parent_l);
    if (parent_dead)
        f.parent_l = NULL;
    lineUnref(f.child_l);
#else
    const bool child_dead = ! lineIsAlive(f.child_l);
    lineUnref(f.child_l);
    if (child_dead)
        f.child_l = NULL;
    lineUnref(f.parent_l);
#endif
    fixtureTeardown(&f);
}

static void caseSpliceBatchAdmission(unsigned mode)
{
    twfSetCase("whole batch admits at ordinary-cost equality or refuses before any callback");
    pq_fixture_t f;
    pqSetup(&f);
    if (! pqHaveMaximumPipe(&f))
    {
        fixtureTeardown(&f);
        return;
    }
    pqBatchLength = kMuxMaxDataFrameLength + 3U;
    sbuf_t *large =
        bufferpoolGetBestFit(f.env.pool, kMuxMaxDataFrameLength, bufferpoolGetLargeBufferPadding(f.env.pool));
    sbuf_t      *small         = bufferpoolGetBestFit(f.env.pool, 3, bufferpoolGetLargeBufferPadding(f.env.pool));
    const size_t ordinary_cost = sbufGetAllocationCharge(large) + sbufGetAllocationCharge(small);
    bufferpoolReuseBuffer(f.env.pool, large);
    bufferpoolReuseBuffer(f.env.pool, small);
    pq_tstate_t *ts                  = tunnelGetState(f.mux);
    ts->parent_write_limit           = (uint32_t) ordinary_cost - (mode == 1 ? 1U : 0U);
    ts->parent_write_pause_threshold = (uint32_t) ordinary_cost - 1U;
    if (mode == 0)
        pqParentPause(&f);
    sbuf_t *input = pqLargeSplice(&f);
    if (mode == 2)
        g_reject_next_queue_reallocation = true;
    if (mode == 3)
        g_reject_queue_after = 1; // Stage reservation succeeds; parent publication reservation fails.
    lineRef(f.parent_l);
    lineRef(f.child_l);
    pqSend(f.mux, f.child_l, input);
    twfRequire(pqDeliveries == 0, "refused or paused batch emitted output");
    if (mode == 0)
    {
        twfRequire(pqOutput(&f)->charge <= ordinary_cost && bufferqueueGetBufCount(&pqOutput(&f)->pending) == 2,
                   "greedy pipe selection refused ordinary-fitting batch equality");
    }
    else
    {
        twfRequireLineStateZeroed(f.parent_l, f.mux, "refused batch retained parent state");
    }
#ifdef MUX_OUTPUT_CLIENT
    const bool parent_dead = ! lineIsAlive(f.parent_l);
    lineUnref(f.parent_l);
    if (parent_dead)
        f.parent_l = NULL;
    lineUnref(f.child_l);
#else
    const bool child_dead = ! lineIsAlive(f.child_l);
    lineUnref(f.child_l);
    if (child_dead)
        f.child_l = NULL;
    lineUnref(f.parent_l);
#endif
    fixtureTeardown(&f);
}
#endif
