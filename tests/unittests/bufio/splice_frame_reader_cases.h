/*
 * Covers: complete/incremental frame reading, admission, FIFO, retained charge and retirement.
 * Setup: Pool and ordinary/pipe source fixtures from bufio_contract_test.c.
 * CTest: waterwall.bufio_contract_unit; waterwall.bufio_contract_no_splice_unit.
 */
#include "splice_frame_reader.h"

static sbuf_t *frameReaderOversized(buffer_pool_t *pool, const void *bytes, uint32_t count)
{
    sbuf_t *buf = bufferpoolGetBestFit(pool, 128U * 1024U, bufferpoolGetLargeBufferPadding(pool));
    sbufSetLength(buf, count);
    memoryCopy(sbufGetMutablePtr(buf), bytes, count);
    return buf;
}

static void testFrameReaderFragments(buffer_pool_t *pool)
{
    testCaseSet("frame reader: fragmented headers/bodies and empty frames");
    splice_frame_reader_t r;
    spliceframereaderInit(&r, pool, 2, 64, 128U * 1024U, false);
    const uint8_t wire[] = {0, 3, 'A', 'B', 'C', 0, 0, 0, 1, 'D'};
    unsigned      frames = 0;
    for (unsigned i = 0; i < sizeof(wire); ++i)
    {
        require(spliceframereaderAdmit(&r, streamTestBytes(pool, wire + i, 1)) == kSpliceFrameDrain,
                "fragment did not begin a new outer drain");
        const uint8_t *header = spliceframereaderPeekHeader(&r);
        if (header == NULL)
            require(! spliceframereaderBodyReady(&r, 0), "incomplete header appeared ready for an empty body");
        else if (spliceframereaderBodyReady(&r, header[1]))
        {
            const uint32_t bytes = header[1];
            if (frames == 1)
            {
                require(bytes == 0, "zero-body frame boundary changed");
                spliceframereaderDiscardFrame(&r, 0);
            }
            else
                streamCheckBytes(
                    pool, spliceframereaderTakeFrame(&r, bytes), frames == 0 ? "ABC" : "D", frames == 0 ? 3 : 1);
            ++frames;
        }
        require(spliceframereaderEndDrain(&r), "fragment retention was refused");
    }
    require(frames == 3 && spliceframereaderLength(&r) == 0 && spliceframereaderCharge(&r) == 0,
            "fragmented frames were lost or retained after delivery");
    spliceframereaderDestroy(&r);
    require(! spliceframereaderIsAttached(&r), "destroyed reader remained attached");
}

static void testFrameReaderNested(buffer_pool_t *pool)
{
    testCaseSet("frame reader: nested FIFO, exact byte limit and ownership on refusal");
    splice_frame_reader_t r;
    spliceframereaderInit(&r, pool, 2, 6, 128U * 1024U, false);
    const uint8_t first[] = {0, 1, 'A', 0, 1, 'B'};
    const uint8_t newer[] = {0, 1, 'C'};
    require(spliceframereaderAdmit(&r, streamTestBytes(pool, first, sizeof(first))) == kSpliceFrameDrain,
            "initial batch did not start drain");
    streamCheckBytes(pool, spliceframereaderTakeFrame(&r, 1), "A", 1);
    require(spliceframereaderAdmit(&r, streamTestBytes(pool, newer, sizeof(newer))) == kSpliceFrameQueued,
            "nested exact byte limit was refused or started recursive delivery");
    require(spliceframereaderAdmit(&r, streamTestBytes(pool, "", 0)) == kSpliceFrameEmpty &&
                spliceframereaderLength(&r) == 6,
            "empty input disturbed an active drain");
    streamCheckBytes(pool, spliceframereaderTakeFrame(&r, 1), "B", 1);
    streamCheckBytes(pool, spliceframereaderTakeFrame(&r, 1), "C", 1);
    require(spliceframereaderEndDrain(&r), "nested FIFO failed to settle");
    spliceframereaderDestroy(&r);

    spliceframereaderInit(&r, pool, 2, 6, 128U * 1024U, false);
    require(spliceframereaderAdmit(&r, streamTestBytes(pool, first, sizeof(first))) == kSpliceFrameDrain,
            "byte refusal fixture did not start drain");
    sbuf_t *refused = streamTestBytes(pool, "X", 1);
    require(spliceframereaderAdmit(&r, refused) == kSpliceFrameByteLimit && spliceframereaderLength(&r) == 6 &&
                memoryEqual(spliceframereaderPeekHeader(&r), first, 2),
            "nested byte overflow changed older input");
    sbuf_t *recycled = streamTestBytes(pool, "", 0);
    require(recycled == refused, "byte refusal did not recycle submitted input");
    bufferpoolReuseBuffer(pool, recycled);
    spliceframereaderDestroy(&r);
}

static void testFrameReaderSettlement(buffer_pool_t *pool)
{
    buffer_pool_fit_t fit;
    require(bufferpoolQueryBestFit(pool, 1, bufferpoolGetLargeBufferPadding(pool), &fit), "invalid test pool geometry");
    const uint8_t frame[] = {0, 1, 'B'};
    for (unsigned refusal = 0; refusal < 2; ++refusal)
    {
        testCaseSet("frame reader: compact nested input before accepting or refusing charge");
        splice_frame_reader_t r;
        spliceframereaderInit(&r, pool, 2, 3, fit.allocation_charge - refusal, false);
        const uint8_t empty[] = {0, 0};
        require(spliceframereaderAdmit(&r, streamTestBytes(pool, empty, sizeof(empty))) == kSpliceFrameDrain,
                "empty frame did not start drain");
        spliceframereaderDiscardFrame(&r, 0);
        const splice_frame_admit_t result =
            spliceframereaderAdmit(&r, frameReaderOversized(pool, frame, sizeof(frame)));
        require(result == (refusal ? kSpliceFrameChargeLimit : kSpliceFrameQueued),
                "nested input ignored resulting charge or refused before compaction");
        require(spliceframereaderCharge(&r) == fit.allocation_charge && spliceframereaderLength(&r) == sizeof(frame) &&
                    memoryEqual(spliceframereaderPeekHeader(&r), frame, 2),
                "nested charge settlement lost header, bytes or storage accounting");
        if (! refusal)
        {
            streamCheckBytes(pool, spliceframereaderTakeFrame(&r, 1), "B", 1);
            require(spliceframereaderEndDrain(&r), "settled nested frame could not finish drain");
        }
        spliceframereaderDestroy(&r);
        require(! spliceframereaderIsAttached(&r), "retirement during drain retained the stream");
    }
    for (unsigned refusal = 0; refusal < 2; ++refusal)
    {
        testCaseSet("frame reader: incomplete outer retention settles before return");
        splice_frame_reader_t r;
        spliceframereaderInit(&r, pool, 2, 0, fit.allocation_charge - refusal, false);
        const uint8_t partial[] = {0, 2, 'A'};
        require(spliceframereaderAdmit(&r, frameReaderOversized(pool, partial, sizeof(partial))) == kSpliceFrameDrain,
                "top-level input incorrectly used nested limits");
        require(! spliceframereaderBodyReady(&r, 2), "partial body was ready");
        require(spliceframereaderEndDrain(&r) == ! refusal && spliceframereaderCharge(&r) == fit.allocation_charge,
                "outer settlement ignored the final retained charge");
        if (! refusal)
        {
            require(spliceframereaderAdmit(&r, streamTestBytes(pool, "B", 1)) == kSpliceFrameDrain,
                    "successful EndDrain did not release the drain guard");
            streamCheckBytes(pool, spliceframereaderTakeFrame(&r, 2), "AB", 2);
            require(spliceframereaderEndDrain(&r), "completed partial frame did not settle");
        }
        spliceframereaderDestroy(&r);
    }
}

static void testFrameReaderBatchAndRepresentation(buffer_pool_t *pool)
{
    testCaseSet("frame reader: complete top-level batch drains before storage limits");
    splice_frame_reader_t r;
    spliceframereaderInit(&r, pool, 2, 0, 0, false);
    sbuf_t *empty = streamTestBytes(pool, "", 0);
    require(spliceframereaderAdmit(&r, empty) == kSpliceFrameEmpty, "empty input started a drain");
    const uint8_t batch[] = {0, 1, 'A', 0, 1, 'B'};
    require(spliceframereaderAdmit(&r, streamTestBytes(pool, batch, sizeof(batch))) == kSpliceFrameDrain,
            "complete outer batch was refused before processing");
    streamCheckBytes(pool, spliceframereaderTakeFrame(&r, 1), "A", 1);
    streamCheckBytes(pool, spliceframereaderTakeFrame(&r, 1), "B", 1);
    require(spliceframereaderEndDrain(&r), "empty remainder failed zero charge limit");
    spliceframereaderDestroy(&r);

    for (unsigned splice_output = 0; splice_output < 2; ++splice_output)
        for (unsigned pipe_input = 0; pipe_input < (WW_HAVE_SPLICE ? 2U : 1U); ++pipe_input)
        {
            testCaseSet("frame reader: representation selection preserves bytes and padding");
            spliceframereaderInit(&r, pool, 2, 64, 128U * 1024U, splice_output != 0);
            const uint8_t header[] = {0, 3};
            const uint8_t frame[]  = {0, 3, 'A', 'B', 'C'};
            sbuf_t       *input;
#if WW_HAVE_SPLICE
            if (pipe_input)
                input = makeSpliceTestBuffer(pool, header, sizeof(header), (const uint8_t *) "ABC", 3);
            else
#endif
                input = streamTestBytes(pool, frame, sizeof(frame));
            discard header;
            require(spliceframereaderAdmit(&r, input) == kSpliceFrameDrain, "representation fixture admission failed");
            sbuf_t *body = spliceframereaderTakeFrame(&r, 3);
            require(sbufIsSplice(body) == (pipe_input && splice_output), "reader selected incorrect representation");
            streamCheckBytes(pool, body, "ABC", 3);
            require(spliceframereaderEndDrain(&r), "representation fixture failed to settle");
            spliceframereaderDestroy(&r);
        }
}

static sbuf_t *frameReaderInput(buffer_pool_t *pool, const uint8_t *bytes, uint32_t count, bool pipe_input)
{
#if WW_HAVE_SPLICE
    if (pipe_input)
        return makeSpliceTestBuffer(pool, NULL, 0, bytes, count);
#else
    discard pipe_input;
#endif
    return streamTestBytes(pool, bytes, count);
}

static void testFrameReaderIncremental(buffer_pool_t *pool)
{
    for (unsigned splice_output = 0; splice_output < 2; ++splice_output)
        for (unsigned pipe_input = 0; pipe_input < (WW_HAVE_SPLICE ? 2U : 1U); ++pipe_input)
        {
            testCaseSet("frame reader: fragmented incremental body, bounded chunks and mixed empty/complete frames");
            splice_frame_reader_t r;
            spliceframereaderInit(&r, pool, 2, 64, 128U * 1024U, splice_output != 0);
            const uint8_t first[] = {0, 6, 'A', 'B'};
            require(spliceframereaderAdmit(&r, frameReaderInput(pool, first, 1, pipe_input)) == kSpliceFrameDrain &&
                        spliceframereaderPeekHeader(&r) == NULL && ! spliceframereaderFrameActive(&r),
                    "partial header started an incremental frame");
            require(spliceframereaderEndDrain(&r), "partial header failed settlement");
            require(spliceframereaderAdmit(&r, frameReaderInput(pool, first + 1, 3, pipe_input)) == kSpliceFrameDrain,
                    "first partial body failed admission");
            require(! spliceframereaderBodyReady(&r, 6), "partial body became a complete frame");
            spliceframereaderBeginFrame(&r, 6);
            require(spliceframereaderFrameActive(&r) && spliceframereaderFrameRemaining(&r) == 6 &&
                        spliceframereaderFrameAvailable(&r) == 2,
                    "incremental frame required the complete body");
            sbuf_t *body = spliceframereaderTakeChunk(&r, 2);
            require(sbufIsSplice(body) == (pipe_input && splice_output), "incremental output representation changed");
            streamCheckBytes(pool, body, "AB", 2);
            require(spliceframereaderFrameRemaining(&r) == 4 && spliceframereaderFrameAvailable(&r) == 0 &&
                        spliceframereaderLength(&r) == 2 && spliceframereaderCharge(&r) == 0 &&
                        memoryEqual(spliceframereaderPeekHeader(&r), first, 2),
                    "partial extraction lost the header, retained consumed bytes or changed frame progress");
            require(spliceframereaderEndDrain(&r), "partial extraction failed settlement");
            require(spliceframereaderAdmit(&r, frameReaderInput(pool, (const uint8_t *) "C", 1, pipe_input)) ==
                        kSpliceFrameDrain,
                    "incremental continuation failed admission");
            spliceframereaderDiscardChunk(&r, 1);
            require(spliceframereaderFrameRemaining(&r) == 3 && spliceframereaderLength(&r) == 2,
                    "incremental discard ended the frame early");
            require(spliceframereaderEndDrain(&r), "partial discard failed settlement");

            const uint8_t suffix[] = {'D', 'E', 'F', 0, 0, 0, 0, 0, 1, 'G'};
            require(spliceframereaderAdmit(&r, frameReaderInput(pool, suffix, sizeof(suffix), pipe_input)) ==
                            kSpliceFrameDrain &&
                        spliceframereaderFrameAvailable(&r) == 3,
                    "available chunk crossed into the next frame");
            streamCheckBytes(pool, spliceframereaderTakeChunk(&r, 2), "DE", 2);
            require(spliceframereaderFrameRemaining(&r) == 1 && spliceframereaderFrameAvailable(&r) == 1 &&
                        memoryEqual(spliceframereaderPeekHeader(&r), first, 2),
                    "nonfinal chunk gathered the following header");
            streamCheckBytes(pool, spliceframereaderTakeChunk(&r, 1), "F", 1);
            require(! spliceframereaderFrameActive(&r) && spliceframereaderFrameRemaining(&r) == 0 &&
                        spliceframereaderFrameAvailable(&r) == 0 && spliceframereaderLength(&r) == 7 &&
                        spliceframereaderPeekHeader(&r)[1] == 0,
                    "final chunk did not complete before returning");
            spliceframereaderBeginFrame(&r, 0);
            require(spliceframereaderFrameActive(&r) && spliceframereaderFrameAvailable(&r) == 0,
                    "empty incremental frame completed without consumption");
            streamCheckBytes(pool, spliceframereaderTakeChunk(&r, 0), "", 0);
            spliceframereaderBeginFrame(&r, 0);
            spliceframereaderDiscardChunk(&r, 0);
            require(spliceframereaderBodyReady(&r, 1) && spliceframereaderPeekHeader(&r)[1] == 1,
                    "empty chunks lost the following complete frame");
            streamCheckBytes(pool, spliceframereaderTakeFrame(&r, 1), "G", 1);
            require(spliceframereaderEndDrain(&r) && spliceframereaderLength(&r) == 0 &&
                        spliceframereaderCharge(&r) == 0,
                    "mixed complete/incremental frames retained input");
            spliceframereaderDestroy(&r);
        }
}

static void testFrameReaderIncrementalNested(buffer_pool_t *pool)
{
    testCaseSet("frame reader: incremental progress commits before nested admission and final discard");
    splice_frame_reader_t r;
    spliceframereaderInit(&r, pool, 2, 7, 128U * 1024U, false);
    const uint8_t first[] = {0, 6, 'A', 'B'};
    require(spliceframereaderAdmit(&r, streamTestBytes(pool, first, sizeof(first))) == kSpliceFrameDrain,
            "incremental nested fixture failed admission");
    spliceframereaderBeginFrame(&r, 6);
    streamCheckBytes(pool, spliceframereaderTakeChunk(&r, 2), "AB", 2);
    require(spliceframereaderAdmit(&r, streamTestBytes(pool, "CDE", 3)) == kSpliceFrameQueued &&
                spliceframereaderFrameRemaining(&r) == 4 && spliceframereaderFrameAvailable(&r) == 3,
            "nested input restarted the incremental frame");
    streamCheckBytes(pool, spliceframereaderTakeChunk(&r, 2), "CD", 2);
    const uint8_t tail[] = {'F', 0, 1, 'G'};
    require(spliceframereaderAdmit(&r, streamTestBytes(pool, tail, sizeof(tail))) == kSpliceFrameQueued &&
                spliceframereaderLength(&r) == 7 && spliceframereaderFrameAvailable(&r) == 2,
            "nested admission counted consumed body bytes or crossed the current frame");
    spliceframereaderDiscardChunk(&r, 2);
    require(! spliceframereaderFrameActive(&r) && spliceframereaderPeekHeader(&r)[1] == 1,
            "final discard did not finish before nested reentry");
    const uint8_t newer[] = {0, 1, 'H'};
    require(spliceframereaderAdmit(&r, streamTestBytes(pool, newer, sizeof(newer))) == kSpliceFrameQueued,
            "completed frame cleared the active drain guard");
    streamCheckBytes(pool, spliceframereaderTakeFrame(&r, 1), "G", 1);
    streamCheckBytes(pool, spliceframereaderTakeFrame(&r, 1), "H", 1);
    require(spliceframereaderEndDrain(&r), "incremental nested input failed settlement");
    spliceframereaderDestroy(&r);
}

static void testFrameReaderIncrementalRetirement(buffer_pool_t *pool)
{
    testCaseSet("frame reader: active-frame compaction, refusal and retirement");
    buffer_pool_fit_t fit;
    require(bufferpoolQueryBestFit(pool, 1, bufferpoolGetLargeBufferPadding(pool), &fit), "invalid test pool geometry");
    for (unsigned refusal = 0; refusal < 2; ++refusal)
    {
        splice_frame_reader_t r;
        spliceframereaderInit(&r, pool, 2, 3, fit.allocation_charge - refusal, false);
        const uint8_t first[] = {0, 4, 'A', 'B'};
        require(spliceframereaderAdmit(&r, frameReaderOversized(pool, first, sizeof(first))) == kSpliceFrameDrain,
                "active-frame settlement fixture failed admission");
        spliceframereaderBeginFrame(&r, 4);
        streamCheckBytes(pool, spliceframereaderTakeChunk(&r, 1), "A", 1);
        require(spliceframereaderEndDrain(&r) == ! refusal && spliceframereaderCharge(&r) == fit.allocation_charge &&
                    spliceframereaderFrameActive(&r) && spliceframereaderFrameRemaining(&r) == 3 &&
                    spliceframereaderFrameAvailable(&r) == 1 && spliceframereaderLength(&r) == 3 &&
                    memoryEqual(spliceframereaderPeekHeader(&r), first, 2),
                "active-frame settlement lost progress, header or retained-byte accounting");
        if (! refusal)
        {
            require(spliceframereaderAdmit(&r, streamTestBytes(pool, "C", 1)) == kSpliceFrameDrain,
                    "settled active frame did not release the drain guard");
            require(spliceframereaderAdmit(&r, streamTestBytes(pool, "D", 1)) == kSpliceFrameByteLimit &&
                        spliceframereaderFrameRemaining(&r) == 3 && spliceframereaderFrameAvailable(&r) == 2,
                    "nested refusal changed an active frame or ignored its cached header");
        }
        spliceframereaderDestroy(&r);
        require(! spliceframereaderIsAttached(&r) && ! spliceframereaderFrameActive(&r) &&
                    spliceframereaderFrameRemaining(&r) == 0 && spliceframereaderFrameAvailable(&r) == 0,
                "retirement kept active-frame state");
    }
}

static void testSpliceFrameReader(void)
{
    pool_fixture_t fixture = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 64);
    testFrameReaderFragments(fixture.pool);
    testFrameReaderNested(fixture.pool);
    testFrameReaderSettlement(fixture.pool);
    testFrameReaderBatchAndRepresentation(fixture.pool);
    testFrameReaderIncremental(fixture.pool);
    testFrameReaderIncrementalNested(fixture.pool);
    testFrameReaderIncrementalRetirement(fixture.pool);
    poolFixtureDestroy(&fixture);
}
