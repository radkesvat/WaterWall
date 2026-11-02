/*
 * Covers: complete-frame reader admission, FIFO, retained charge and retirement.
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

static void testSpliceFrameReader(void)
{
    pool_fixture_t fixture = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 64);
    testFrameReaderFragments(fixture.pool);
    testFrameReaderNested(fixture.pool);
    testFrameReaderSettlement(fixture.pool);
    testFrameReaderBatchAndRepresentation(fixture.pool);
    poolFixtureDestroy(&fixture);
}
