/*
 * Covers: exact extraction and prefix gathering from an owned head and unbound queue.
 * Setup: Included after splice_stream_cases.h by bufio_contract_test.c; reuses its
 * pool, source pipes, payload checks and syscall fault probes.
 * Cases: all source splits, suffix ownership/accounting, zero-length no-op,
 * whole-head identity, padding repair, pipe exhaustion, partial fallback,
 * incremental cached prefixes, unread suffix restoration and retained-storage compaction.
 * CTest: waterwall.bufio_contract_unit; waterwall.bufio_contract_no_splice_unit.
 */
#include "buffer_queue_range.h"

static void rangeCheckQueue(const buffer_queue_t *queue)
{
    size_t bytes  = 0;
    size_t charge = 0;
    c_foreach(entry, ww_sbuffer_queue_t, queue->q)
    {
        bytes += sbufGetLength(*entry.ref);
        charge += sbufGetQueueCharge(*entry.ref);
    }
    require(queue->budget == NULL && queue->total_len == bytes && queue->total_charge == charge,
            "range extraction left stale queue accounting");
}

static void rangeDestroyInput(buffer_pool_t *pool, sbuf_t *head, buffer_queue_t *queue)
{
    if (head != NULL)
        bufferpoolReuseBuffer(pool, head);
    while ((head = bufferqueuePopFront(queue)) != NULL)
        bufferpoolReuseBuffer(pool, head);
    bufferqueueDestroy(queue);
}

static sbuf_t *rangeTestInput(buffer_pool_t *pool, const uint8_t *bytes, uint32_t length, unsigned mode)
{
#if WW_HAVE_SPLICE
    if (mode != 0)
    {
        const uint32_t prefix = mode == 2 ? min(length, 3U) : 0;
        return makeSpliceTestBuffer(pool, bytes, prefix, bytes + prefix, length - prefix);
    }
#endif
    discard mode;
    return streamTestBytes(pool, bytes, length);
}

static void testBufferRangeSplits(buffer_pool_t *pool)
{
    const uint8_t  wire[] = "abcdefghNEXT";
    const unsigned modes  = WW_HAVE_SPLICE ? 3U : 1U;
    for (unsigned first = 0; first < modes; ++first)
        for (unsigned second = 0; second < modes; ++second)
            for (uint32_t split = 0; split < sizeof(wire); ++split)
            {
                buffer_queue_t queue;
                bufferqueueInitEmpty(&queue);
                sbuf_t *head = rangeTestInput(pool, wire, split, first);
                bufferqueuePushBack(&queue, rangeTestInput(pool, wire + split, sizeof(wire) - 1U - split, second));
                sbuf_t *body = bufferRangeTakeExact(pool, &head, &queue, 8);
                rangeCheckQueue(&queue);
                require((head == NULL ? 0 : sbufGetLength(head)) + queue.total_len == 4,
                        "exact range consumed bytes from the following frame");
                sbuf_t *suffix = bufferRangeTakeExact(pool, &head, &queue, 4);
                rangeCheckQueue(&queue);
                require((head == NULL ? 0 : sbufGetLength(head)) + queue.total_len == 0,
                        "complete range extraction retained payload bytes");
                /* Reading the suffix first proves independent output ownership. */
                streamCheckBytes(pool, suffix, wire + 8, 4);
                streamCheckBytes(pool, body, wire, 8);
                rangeDestroyInput(pool, head, &queue);
            }
}

static void testBufferRangeZeroAndIdentity(buffer_pool_t *pool)
{
    for (unsigned active = 0; active < 3; ++active)
    {
        buffer_queue_t queue;
        bufferqueueInitEmpty(&queue);
        sbuf_t      *head       = active ? streamTestBytes(pool, "head", active == 1 ? 4 : 0) : NULL;
        sbuf_t      *saved_head = head;
        sbuf_t      *empty      = bufferqueuePushBack(&queue, streamTestBytes(pool, "", 0));
        sbuf_t      *tail       = bufferqueuePushBack(&queue, streamTestBytes(pool, "tail", 4));
        const size_t charge     = bufferqueueGetCharge(&queue);
        sbuf_t      *body       = bufferRangeTakeExact(pool, &head, &queue, 0);
        require(! sbufIsSplice(body) && sbufGetLength(body) == 0, "zero range did not return an empty ordinary buffer");
        require(head == saved_head && bufferqueueFront(&queue) == empty && bufferqueueGetBufCount(&queue) == 2 &&
                    bufferqueueGetBufLen(&queue) == 4 && bufferqueueGetCharge(&queue) == charge &&
                    sbufGetLength(tail) == 4,
                "zero range changed active or queued input");
        streamCheckBytes(pool, body, "", 0);
        rangeDestroyInput(pool, head, &queue);
    }

    for (unsigned mode = 0; mode < (WW_HAVE_SPLICE ? 2U : 1U); ++mode)
        for (unsigned queued = 0; queued < 2; ++queued)
        {
            buffer_queue_t queue;
            bufferqueueInitEmpty(&queue);
            sbuf_t *source = rangeTestInput(pool, (const uint8_t *) "body", 4, mode);
            sbuf_t *head   = queued ? NULL : source;
            if (queued)
                source = bufferqueuePushBack(&queue, source);
            sbuf_t *body = bufferRangeTakeExact(pool, &head, &queue, 4);
            require(body == source && head == NULL && bufferqueueGetBufCount(&queue) == 0,
                    "whole suitable head did not transfer its exact retained allocation");
            rangeCheckQueue(&queue);
            streamCheckBytes(pool, body, "body", 4);
            rangeDestroyInput(pool, head, &queue);
        }
}

static void testBufferRangePaddingAndQueuedSuffix(buffer_pool_t *pool)
{
    buffer_queue_t queue;
    bufferqueueInitEmpty(&queue);
    sbuf_t *head = sbufCreateWithPadding(4, 0);
    sbufSetLength(head, 4);
    sbufWrite(head, "body", 4);
    sbuf_t *body = bufferRangeTakeExact(pool, &head, &queue, 4);
    require(head == NULL, "padding repair retained an exhausted head");
    streamCheckBytes(pool, body, "body", 4);

    head                         = streamTestBytes(pool, "ab", 2);
    sbuf_t        *middle        = bufferqueuePushBack(&queue, streamTestBytes(pool, "cdef", 4));
    sbuf_t        *tail          = bufferqueuePushBack(&queue, streamTestBytes(pool, "NEXT", 4));
    const uint32_t tail_cursor   = tail->curpos;
    const uint32_t tail_capacity = tail->capacity;
    const size_t   tail_charge   = sbufGetQueueCharge(tail);
    body                         = bufferRangeTakeExact(pool, &head, &queue, 4);
    require(head == middle && sbufGetLength(head) == 2 && memoryEqual(sbufGetRawPtr(head), "ef", 2),
            "range extraction lost its partially consumed popped head");
    require(bufferqueueFront(&queue) == tail && bufferqueueGetBufCount(&queue) == 1 &&
                bufferqueueGetBufLen(&queue) == 4 && bufferqueueGetCharge(&queue) == tail_charge &&
                tail->curpos == tail_cursor && tail->capacity == tail_capacity && sbufGetLength(tail) == 4 &&
                memoryEqual(sbufGetRawPtr(tail), "NEXT", 4),
            "range extraction mutated a still-queued suffix");
    rangeCheckQueue(&queue);
    streamCheckBytes(pool, body, "abcd", 4);
    streamCheckBytes(pool, bufferRangeTakeExact(pool, &head, &queue, 6), "efNEXT", 6);
    rangeDestroyInput(pool, head, &queue);
}

static void testBufferRangeGatherSplits(buffer_pool_t *pool)
{
    const uint8_t  wire[] = "abcdBODY";
    const unsigned modes  = WW_HAVE_SPLICE ? 3U : 1U;
    for (unsigned first = 0; first < modes; ++first)
        for (unsigned second = 0; second < modes; ++second)
            for (uint32_t split = 0; split < sizeof(wire); ++split)
            {
                buffer_queue_t queue;
                bufferqueueInitEmpty(&queue);
                sbuf_t *head = rangeTestInput(pool, wire, split, first);
                bufferqueuePushBack(&queue, streamTestBytes(pool, "", 0));
                bufferqueuePushBack(&queue, rangeTestInput(pool, wire + split, sizeof(wire) - 1U - split, second));
                uint8_t  prefix[5] = {0, 0, 0, 0, 0xA5};
                uint16_t filled    = 0;
#if WW_HAVE_SPLICE
                streamProbe       = true;
                streamReadBytes   = 0;
                streamSpliceBytes = 0;
#endif
                require(bufferRangeGatherPrefix(pool, &head, &queue, prefix, &filled, 4),
                        "gather rejected an available prefix");
#if WW_HAVE_SPLICE
                streamProbe                 = false;
                const uint32_t first_bytes  = min(split, 4U);
                const uint32_t second_bytes = 4U - first_bytes;
                const uint32_t first_pipe   = first == 0 ? 0 : first_bytes - (first == 2 ? min(first_bytes, 3U) : 0);
                const uint32_t second_pipe = second == 0 ? 0 : second_bytes - (second == 2 ? min(second_bytes, 3U) : 0);
                require(streamReadBytes == first_pipe + second_pipe && streamSpliceBytes == 0,
                        "prefix gather materialized bytes outside the requested metadata");
#endif
                require(filled == 4 && memoryEqual(prefix, wire, 4) && prefix[4] == 0xA5,
                        "prefix gather lost bytes or overran the requested extent");
                require((head == NULL ? 0 : sbufGetLength(head)) + queue.total_len == 4,
                        "prefix gather consumed following body bytes");
                rangeCheckQueue(&queue);
                streamCheckBytes(pool, bufferRangeTakeExact(pool, &head, &queue, 4), wire + 4, 4);
                rangeDestroyInput(pool, head, &queue);
            }
}

static void testBufferRangeGatherIncremental(buffer_pool_t *pool)
{
    const uint8_t wire[] = "abcdef";
    for (unsigned mode = 0; mode < (WW_HAVE_SPLICE ? 3U : 1U); ++mode)
    {
        buffer_queue_t queue;
        bufferqueueInitEmpty(&queue);
        sbuf_t  *head      = NULL;
        uint8_t  prefix[7] = {0};
        uint16_t filled    = 0;
        require(! bufferRangeGatherPrefix(pool, &head, &queue, prefix, &filled, 4) && filled == 0,
                "empty input completed a missing prefix");
        for (uint16_t i = 0; i < sizeof(wire) - 1U; ++i)
        {
            bufferqueuePushBack(&queue, streamTestBytes(pool, "", 0));
            bufferqueuePushBack(&queue, rangeTestInput(pool, wire + i, 1, mode));
            const uint16_t needed = i < 4 ? 4 : 6;
            require(bufferRangeGatherPrefix(pool, &head, &queue, prefix, &filled, needed) == (i + 1U == needed),
                    "incremental gather returned the wrong completion state");
            require(filled == i + 1U && memoryEqual(prefix, wire, filled) && prefix[filled] == 0 && head == NULL &&
                        bufferqueueGetBufCount(&queue) == 0,
                    "incremental gather lost cached progress or retained exhausted input");
            rangeCheckQueue(&queue);
        }
        rangeDestroyInput(pool, head, &queue);
    }
}

static void testBufferRangeGatherNoop(buffer_pool_t *pool)
{
    for (unsigned active = 0; active < 3; ++active)
    {
        buffer_queue_t queue;
        bufferqueueInitEmpty(&queue);
        sbuf_t *head       = active ? streamTestBytes(pool, "head", active == 1 ? 4 : 0) : NULL;
        sbuf_t *saved_head = head;
        sbuf_t *empty      = bufferqueuePushBack(&queue, streamTestBytes(pool, "", 0));
        bufferqueuePushBack(&queue, streamTestBytes(pool, "tail", 4));
        const size_t charge    = bufferqueueGetCharge(&queue);
        uint8_t      prefix[5] = "abcd";
        uint16_t     filled    = 0;
        require(bufferRangeGatherPrefix(pool, &head, &queue, prefix, &filled, 0) && filled == 0,
                "zero prefix request did not succeed");
        filled = 4;
        require(bufferRangeGatherPrefix(pool, &head, &queue, prefix, &filled, 4) &&
                    bufferRangeGatherPrefix(pool, &head, &queue, prefix, &filled, 1),
                "cached prefix did not satisfy an equal or earlier parser checkpoint");
        require(filled == 4 && memoryEqual(prefix, "abcd", sizeof(prefix)) && head == saved_head &&
                    (head == NULL || sbufGetLength(head) == (active == 1 ? 4U : 0U)) &&
                    bufferqueueFront(&queue) == empty && bufferqueueGetBufCount(&queue) == 2 &&
                    bufferqueueGetBufLen(&queue) == 4 && bufferqueueGetCharge(&queue) == charge,
                "satisfied gather changed cached bytes or input ownership");
        rangeCheckQueue(&queue);
        rangeDestroyInput(pool, head, &queue);
    }
}

static void testBufferRangeRestoreSuffix(buffer_pool_t *pool)
{
    for (unsigned mode = 0; mode < (WW_HAVE_SPLICE ? 3U : 1U); ++mode)
    {
        buffer_queue_t queue;
        bufferqueueInitEmpty(&queue);
        bufferqueuePushBack(&queue, rangeTestInput(pool, (const uint8_t *) "abcdBODY", 8, mode));
        sbuf_t      *tail        = bufferqueuePushBack(&queue, streamTestBytes(pool, "NEXT", 4));
        const size_t tail_charge = sbufGetQueueCharge(tail);
        sbuf_t      *head        = bufferqueuePopFront(&queue);
        uint8_t      prefix[4];
        uint16_t     filled = 0;
        require(bufferRangeGatherPrefix(pool, &head, &queue, prefix, &filled, 4) && filled == 4 &&
                    memoryEqual(prefix, "abcd", 4),
                "restore fixture did not consume its cached prefix");
        require(head != NULL && sbufGetLength(head) == 4 && bufferqueueFront(&queue) == tail &&
                    bufferqueueGetBufLen(&queue) == 4 && bufferqueueGetCharge(&queue) == tail_charge,
                "gather mutated a still-queued suffix");
        const size_t head_charge = sbufGetQueueCharge(head);
        bufferRangeRestoreHead(&head, &queue);
        require(head == NULL && bufferqueueGetBufCount(&queue) == 2 && bufferqueueGetBufLen(&queue) == 8 &&
                    bufferqueueGetCharge(&queue) == head_charge + tail_charge,
                "head restoration lost ownership or miscounted the unread suffix");
        const sbuf_t *restored = bufferqueueFront(&queue);
        bufferRangeRestoreHead(&head, &queue);
        require(head == NULL && bufferqueueFront(&queue) == restored && bufferqueueGetBufCount(&queue) == 2 &&
                    bufferqueueGetBufLen(&queue) == 8 && bufferqueueGetCharge(&queue) == head_charge + tail_charge,
                "null head restoration changed queued ownership");
        rangeCheckQueue(&queue);
        /* Ordinary Debug insertion may replace the restored allocation. Consume
         * through the queue's current owner, never through the former head. */
        streamCheckBytes(pool, bufferRangeTakeExact(pool, &head, &queue, 8), "BODYNEXT", 8);
        rangeDestroyInput(pool, head, &queue);
    }
}

static void testBufferRangeRetainedStorage(buffer_pool_t *pool)
{
    buffer_queue_t queue;
    bufferqueueInitEmpty(&queue);
    sbuf_t *head   = streamTestBytes(pool, "ab", 2);
    sbuf_t *tail   = bufferqueuePushBack(&queue, streamTestBytes(pool, "cd", 2));
    sbuf_t *saved  = head;
    size_t  charge = sbufGetQueueCharge(head) + bufferqueueGetCharge(&queue);
    require(bufferRangeSettleRetained(pool, &head, &queue, charge, 2) && head == saved &&
                bufferqueueFront(&queue) == tail,
            "settling within the exact limits changed input ownership");
    require(bufferRangeSettleRetained(pool, &head, &queue, charge, 1) && head == saved &&
                bufferqueueGetBufCount(&queue) == 0 && sbufGetLength(head) == 4,
            "entry pressure did not reuse existing head append room");
    rangeCheckQueue(&queue);
    streamCheckBytes(pool, head, "abcd", 4);
    head = bufferpoolGetLargeBuffer(pool);
    sbufSetLength(head, 4);
    sbufWrite(head, "body", 4);
    saved = head;
    buffer_pool_fit_t fit;
    require(bufferpoolQueryBestFit(pool, 4, bufferpoolGetLargeBufferPadding(pool), &fit),
            "retained-storage fixture geometry failed");
    require(! bufferRangeSettleRetained(pool, &head, &queue, fit.allocation_charge - 1U, 1) && head == saved &&
                sbufGetLength(head) == 4,
            "unrepresentable compact budget consumed input");
    require(bufferRangeSettleRetained(pool, &head, &queue, fit.allocation_charge, 1) && head != saved &&
                sbufGetQueueCharge(head) <= fit.allocation_charge,
            "single oversized head did not compact to fitting storage");
    streamCheckBytes(pool, head, "body", 4);

    /* Pressure on each appended fragment must reuse assembly room instead of
     * repeatedly copying the whole growing body. This is only a 12 KiB body. */
    uint8_t expected[12 * 1024];
    for (uint32_t i = 0; i < sizeof(expected); ++i)
        expected[i] = (uint8_t) i;
    head                  = NULL;
    unsigned replacements = 0;
    for (uint32_t offset = 0; offset < sizeof(expected); offset += 256)
    {
        bufferqueuePushBack(&queue, streamTestBytes(pool, expected + offset, 256));
        saved = head;
        require(bufferRangeSettleRetained(pool, &head, &queue, 128 * 1024, 1),
                "bounded fragmented body could not compact");
        if (head != NULL && saved != head)
            ++replacements;
        rangeCheckQueue(&queue);
    }
    require(replacements <= 3, "retained body repeatedly copied its accumulated prefix");
    streamCheckBytes(pool, bufferRangeTakeExact(pool, &head, &queue, sizeof(expected)), expected, sizeof(expected));
    rangeDestroyInput(pool, head, &queue);
}

#if WW_HAVE_SPLICE
static void testBufferRangeRetainedSplice(buffer_pool_t *pool)
{
    for (unsigned mode = 1; mode <= 2; ++mode)
        for (unsigned fault = 0; fault <= 1; ++fault)
        {
            buffer_queue_t queue;
            bufferqueueInitEmpty(&queue);
            sbuf_t *head = rangeTestInput(pool, (const uint8_t *) "abc", 3, mode);
            bufferqueuePushBack(&queue, rangeTestInput(pool, (const uint8_t *) "def", 3, 1));
            streamProbe         = true;
            streamTransferFault = fault ? 3 : 0;
            require(bufferRangeSettleRetained(pool, &head, &queue, 128 * 1024, 1),
                    "splice retention could not compact");
            streamProbe         = false;
            streamTransferFault = 0;
            require(sbufIsSplice(head) == ! fault && bufferqueueGetBufCount(&queue) == 0,
                    "retained splice assembly did not preserve pipes or select complete fallback");
            rangeCheckQueue(&queue);
            streamCheckBytes(pool, head, "abcdef", 6);
            rangeDestroyInput(pool, NULL, &queue);
        }

    /* A valid current pipe charge can exceed the cap after appending, even
     * though ordinary storage fits: splice and ordinary padding may differ. */
    pool_fixture_t fixture = poolFixtureCreate(256, 128, 0, 0);
    buffer_queue_t queue;
    bufferqueueInitEmpty(&queue);
    uint8_t wire[80] = {0};
    sbuf_t *head     = makeSpliceTestBuffer(fixture.pool, NULL, 0, wire, 48);
    bufferqueuePushBack(&queue, streamTestBytes(fixture.pool, wire + 48, 32));
    buffer_pool_fit_t fit;
    require(bufferpoolQueryBestFit(fixture.pool, sizeof(wire), 0, &fit) &&
                sbufGetQueueCharge(head) <= fit.allocation_charge,
            "differing splice padding fixture does not fit its initial head");
    require(bufferRangeSettleRetained(fixture.pool, &head, &queue, fit.allocation_charge, 1) && ! sbufIsSplice(head) &&
                sbufGetQueueCharge(head) <= fit.allocation_charge,
            "splice append bypassed the final retained charge limit");
    streamCheckBytes(fixture.pool, head, wire, sizeof(wire));
    rangeDestroyInput(fixture.pool, NULL, &queue);
    poolFixtureDestroy(&fixture);
}

static void testBufferRangeSpliceFallback(buffer_pool_t *pool)
{
    const unsigned faults[] = {1, 3, 5};
    for (size_t i = 0; i < ARRAY_SIZE(faults); ++i)
    {
        buffer_queue_t queue;
        bufferqueueInitEmpty(&queue);
        sbuf_t   *head      = makeSpliceTestBuffer(pool, NULL, 0, (const uint8_t *) "abcdef", 6);
        const int source_fd = sbufSpliceMetadata(head).pipefd[0];
        streamProbe         = true;
        streamTransferFault = faults[i];
        streamReadBytes     = 0;
        streamSpliceBytes   = 0;
        sbuf_t *body        = bufferRangeTakeExact(pool, &head, &queue, 3);
        streamProbe         = false;
        streamTransferFault = 0;
        const bool fallback = faults[i] != 1;
        require(sbufIsSplice(body) == ! fallback && streamReadBytes == (fallback ? 3U : 0U),
                "range fault did not select complete ordinary fallback or preserve the splice path");
        require(streamSpliceBytes == (faults[i] == 5 ? 1U : (fallback ? 0U : 3U)),
                "range fault lost short-transfer progress");
        require(head != NULL && sbufGetLength(head) == 3 && sbufSpliceMetadata(head).pipefd[0] == source_fd,
                "range fallback changed source suffix ownership");
        streamCheckBytes(pool, bufferRangeTakeExact(pool, &head, &queue, 3), "def", 3);
        streamCheckBytes(pool, body, "abc", 3);
        rangeDestroyInput(pool, head, &queue);
    }

    buffer_queue_t queue;
    bufferqueueInitEmpty(&queue);
    sbuf_t                      *head = makeSpliceTestBuffer(pool, NULL, 0, (const uint8_t *) "abcdef", 6);
    test_splice_inventory_hold_t held = testSpliceInventoryHoldAvailable(pool);
    require(bufferpoolGetSpliceBuffer(pool) == NULL, "range inventory fixture did not exhaust destination pipes");
    sbuf_t *body = bufferRangeTakeExact(pool, &head, &queue, 3);
    require(! sbufIsSplice(body), "range extraction failed to fall back after pipe checkout refusal");
    streamCheckBytes(pool, body, "abc", 3);
    streamCheckBytes(pool, bufferRangeTakeExact(pool, &head, &queue, 3), "def", 3);
    rangeDestroyInput(pool, head, &queue);
    testSpliceInventoryReleaseHeld(&held);

    /* Preserve wrapper-based selection even when only its resident prefix is
     * requested. The unrequested private-pipe suffix stays independently owned. */
    for (uint32_t pipe_bytes = 0; pipe_bytes <= 4; pipe_bytes += 4)
    {
        bufferqueueInitEmpty(&queue);
        head = makeSpliceTestBuffer(pool, (const uint8_t *) "abcd", 4, (const uint8_t *) "PIPE", pipe_bytes);
        body = bufferRangeTakeExact(pool, &head, &queue, 2);
        require(sbufIsSplice(body), "resident-prefix range changed wrapper-based representation selection");
        streamCheckBytes(pool, body, "ab", 2);
        streamCheckBytes(pool, bufferRangeTakeExact(pool, &head, &queue, 2 + pipe_bytes), "cdPIPE", 2 + pipe_bytes);
        rangeDestroyInput(pool, head, &queue);
    }
}
#endif

static void testBufferQueueRangeContracts(void)
{
    pool_fixture_t fixture = poolFixtureCreate(32768, 4096, 64, 64);
    testBufferRangeSplits(fixture.pool);
    testBufferRangeZeroAndIdentity(fixture.pool);
    testBufferRangePaddingAndQueuedSuffix(fixture.pool);
    testBufferRangeGatherSplits(fixture.pool);
    testBufferRangeGatherIncremental(fixture.pool);
    testBufferRangeGatherNoop(fixture.pool);
    testBufferRangeRestoreSuffix(fixture.pool);
    testBufferRangeRetainedStorage(fixture.pool);
#if WW_HAVE_SPLICE
    testBufferRangeRetainedSplice(fixture.pool);
    testBufferRangeSpliceFallback(fixture.pool);
#endif
    poolFixtureDestroy(&fixture);
}
