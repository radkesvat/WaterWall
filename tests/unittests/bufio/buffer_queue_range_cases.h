/*
 * Covers: exact extraction from an owned head and unbound mixed-buffer queue.
 * Setup: Included after splice_stream_cases.h by bufio_contract_test.c; reuses its
 * pool, source pipes, payload checks and syscall fault probes.
 * Cases: all source splits, suffix ownership/accounting, zero-length no-op,
 * whole-head identity, padding repair, pipe exhaustion and partial fallback.
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

#if WW_HAVE_SPLICE
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
#if WW_HAVE_SPLICE
    testBufferRangeSpliceFallback(fixture.pool);
#endif
    poolFixtureDestroy(&fixture);
}
