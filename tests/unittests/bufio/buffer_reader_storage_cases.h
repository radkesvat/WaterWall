/*
 * Covers: exact extraction, prefix gathering and retained-storage compaction through
 * the staged reader API. Included after splice_stream_cases.h for pool, source-pipe,
 * payload and syscall-fault fixtures; runs inside the reader's owner-worker fixture.
 * Cases: all source splits, independent suffix ownership, zero bodies, exact-head
 * identity, padding repair, partial pipe fallback, incremental metadata and growth.
 * CTest: waterwall.bufio_contract_unit; waterwall.bufio_contract_no_splice_unit.
 */
#include "buffer_reader.h"

static sbuf_t *readerTestInput(buffer_pool_t *pool, const uint8_t *bytes, uint32_t length, unsigned mode)
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

/* The successful push updates input to the retained allocation, including Debug
 * queue replacement. The returned pointer is borrowed, never another owner. */
static sbuf_t *readerTestPush(buffer_reader_t *reader, sbuf_t *input)
{
    require(bufferreaderTryPush(reader, &input, SIZE_MAX), "reader fixture input was refused");
    return input;
}

static void testBufferReaderExtractionSplits(buffer_pool_t *pool)
{
    const uint8_t  wire[] = "abcdefghNEXT";
    const unsigned modes  = WW_HAVE_SPLICE ? 3U : 1U;
    for (unsigned first = 0; first < modes; ++first)
        for (unsigned second = 0; second < modes; ++second)
            for (uint32_t split = 0; split < sizeof(wire); ++split)
            {
                uint8_t         header[1];
                buffer_reader_t reader;
                bufferreaderInit(&reader, pool, header, sizeof(header));
                readerTestPush(&reader, readerTestInput(pool, wire, split, first));
                readerTestPush(&reader, readerTestInput(pool, wire + split, sizeof(wire) - 1U - split, second));
                sbuf_t *body = bufferreaderTakeBody(&reader, 8);
                require(bufferreaderLength(&reader) == 4 && bufferreaderBodyBytes(&reader) == 4,
                        "exact extraction consumed the following frame");
                sbuf_t *suffix = bufferreaderTakeBody(&reader, 4);
                require(bufferreaderLength(&reader) == 0 && bufferreaderBodyBytes(&reader) == 0,
                        "complete extraction retained payload bytes");
                /* Reading the suffix first proves independent output ownership. */
                streamCheckBytes(pool, suffix, wire + 8, 4);
                streamCheckBytes(pool, body, wire, 8);
                bufferreaderDestroy(&reader);
            }
}

static void testBufferReaderZeroAndIdentity(buffer_pool_t *pool)
{
    for (unsigned active = 0; active < 2; ++active)
    {
        uint8_t         header[1];
        buffer_reader_t reader;
        bufferreaderInit(&reader, pool, header, sizeof(header));
        sbuf_t *head = NULL;
        if (active)
        {
            head = readerTestPush(&reader, streamTestBytes(pool, "Hhead", 5));
            require(bufferreaderGather(&reader, 1), "zero-body fixture could not activate its head");
            bufferreaderConsumeHeader(&reader);
        }
        sbuf_t      *empty  = readerTestPush(&reader, streamTestBytes(pool, "", 0));
        sbuf_t      *tail   = readerTestPush(&reader, streamTestBytes(pool, "tail", 4));
        const size_t charge = bufferreaderCharge(&reader);
        sbuf_t      *body   = bufferreaderTakeBody(&reader, 0);
        require(! sbufIsSplice(body) && sbufGetLength(body) == 0, "zero body was not an empty ordinary buffer");
        require(bufferreaderCharge(&reader) == charge && bufferreaderEntryCount(&reader) == 2U + active &&
                    bufferreaderLength(&reader) == 4U + 4U * active,
                "zero body changed input accounting");
        streamCheckBytes(pool, body, "", 0);
        if (active)
        {
            body = bufferreaderTakeChunk(&reader);
            require(body == head, "zero body replaced the active head");
            streamCheckBytes(pool, body, "head", 4);
        }
        body = bufferreaderTakeChunk(&reader);
        require(body == empty, "zero body consumed an empty input entry");
        streamCheckBytes(pool, body, "", 0);
        body = bufferreaderTakeChunk(&reader);
        require(body == tail && bufferreaderCharge(&reader) == 0, "zero body replaced its queued suffix");
        streamCheckBytes(pool, body, "tail", 4);
        bufferreaderDestroy(&reader);
    }

    for (unsigned mode = 0; mode < (WW_HAVE_SPLICE ? 2U : 1U); ++mode)
        for (unsigned active = 0; active < 2; ++active)
        {
            uint8_t         header[1];
            buffer_reader_t reader;
            bufferreaderInit(&reader, pool, header, sizeof(header));
            sbuf_t *source = readerTestPush(
                &reader, readerTestInput(pool, (const uint8_t *) (active ? "Hbody" : "body"), active ? 5 : 4, mode));
            if (active)
            {
                require(bufferreaderGather(&reader, 1), "identity fixture could not activate its head");
                bufferreaderConsumeHeader(&reader);
            }
            sbuf_t *body = bufferreaderTakeBody(&reader, 4);
            require(body == source && bufferreaderEntryCount(&reader) == 0 && bufferreaderCharge(&reader) == 0,
                    "whole suitable input did not transfer its retained allocation");
            streamCheckBytes(pool, body, "body", 4);
            bufferreaderDestroy(&reader);
        }
}

static void testBufferReaderPaddingAndQueuedSuffix(buffer_pool_t *pool)
{
    uint8_t         header[1];
    buffer_reader_t reader;
    bufferreaderInit(&reader, pool, header, sizeof(header));
    sbuf_t *input = sbufCreateWithPadding(4, 0);
    sbufSetLength(input, 4);
    sbufWrite(input, "body", 4);
    readerTestPush(&reader, input);
    streamCheckBytes(pool, bufferreaderTakeBody(&reader, 4), "body", 4);
    require(bufferreaderEntryCount(&reader) == 0, "padding repair retained exhausted input");

    readerTestPush(&reader, streamTestBytes(pool, "ab", 2));
    sbuf_t        *middle        = readerTestPush(&reader, streamTestBytes(pool, "cdef", 4));
    sbuf_t        *tail          = readerTestPush(&reader, streamTestBytes(pool, "NEXT", 4));
    const uint32_t tail_cursor   = tail->curpos;
    const uint32_t tail_capacity = tail->capacity;
    const size_t   tail_charge   = sbufGetQueueCharge(tail);
    sbuf_t        *body          = bufferreaderTakeBody(&reader, 4);
    require(bufferreaderHeadLength(&reader) == 2 && bufferreaderEntryCount(&reader) == 2 &&
                bufferreaderLength(&reader) == 6,
            "extraction lost its partially consumed input");
    require(tail->curpos == tail_cursor && tail->capacity == tail_capacity && sbufGetLength(tail) == 4 &&
                memoryEqual(sbufGetRawPtr(tail), "NEXT", 4),
            "extraction mutated a still-queued suffix");
    streamCheckBytes(pool, body, "abcd", 4);
    body = bufferreaderTakeChunk(&reader);
    require(body == middle && bufferreaderCharge(&reader) == tail_charge && bufferreaderEntryCount(&reader) == 1,
            "partial extraction changed suffix ownership or charge");
    streamCheckBytes(pool, body, "ef", 2);
    body = bufferreaderTakeBody(&reader, 4);
    require(body == tail && bufferreaderCharge(&reader) == 0, "queued suffix lost its exact allocation");
    streamCheckBytes(pool, body, "NEXT", 4);
    bufferreaderDestroy(&reader);
}

static void testBufferReaderGatherSplits(buffer_pool_t *pool)
{
    const uint8_t  wire[] = "abcdBODY";
    const unsigned modes  = WW_HAVE_SPLICE ? 3U : 1U;
    for (unsigned first = 0; first < modes; ++first)
        for (unsigned second = 0; second < modes; ++second)
            for (uint32_t split = 0; split < sizeof(wire); ++split)
            {
                uint8_t         header[5] = {0, 0, 0, 0, 0xA5};
                buffer_reader_t reader;
                bufferreaderInit(&reader, pool, header, sizeof(header));
                readerTestPush(&reader, readerTestInput(pool, wire, split, first));
                readerTestPush(&reader, streamTestBytes(pool, "", 0));
                readerTestPush(&reader, readerTestInput(pool, wire + split, sizeof(wire) - 1U - split, second));
#if WW_HAVE_SPLICE
                streamProbe       = true;
                streamReadBytes   = 0;
                streamSpliceBytes = 0;
#endif
                require(bufferreaderGather(&reader, 4), "gather rejected an available prefix");
#if WW_HAVE_SPLICE
                streamProbe                 = false;
                const uint32_t first_bytes  = min(split, 4U);
                const uint32_t second_bytes = 4U - first_bytes;
                const uint32_t first_pipe   = first == 0 ? 0 : first_bytes - (first == 2 ? min(first_bytes, 3U) : 0);
                const uint32_t second_pipe = second == 0 ? 0 : second_bytes - (second == 2 ? min(second_bytes, 3U) : 0);
                require(streamReadBytes == first_pipe + second_pipe && streamSpliceBytes == 0,
                        "gather materialized bytes outside the requested metadata");
#endif
                require(bufferreaderHeaderLength(&reader) == 4 && memoryEqual(header, wire, 4) && header[4] == 0xA5,
                        "gather lost bytes or overran the requested extent");
                require(bufferreaderLength(&reader) == 8 && bufferreaderBodyBytes(&reader) == 4,
                        "gather lost cached accounting or consumed the body");
                streamCheckBytes(pool, bufferreaderTakeBody(&reader, 4), wire + 4, 4);
                bufferreaderDestroy(&reader);
            }
}

static void testBufferReaderGatherIncremental(buffer_pool_t *pool)
{
    const uint8_t wire[] = "abcdef";
    for (unsigned mode = 0; mode < (WW_HAVE_SPLICE ? 3U : 1U); ++mode)
    {
        uint8_t         header[7] = {0};
        buffer_reader_t reader;
        bufferreaderInit(&reader, pool, header, sizeof(header));
        require(! bufferreaderGather(&reader, 4) && bufferreaderHeaderLength(&reader) == 0,
                "empty input completed a missing prefix");
        for (uint16_t i = 0; i < sizeof(wire) - 1U; ++i)
        {
            readerTestPush(&reader, streamTestBytes(pool, "", 0));
            readerTestPush(&reader, readerTestInput(pool, wire + i, 1, mode));
            const uint16_t needed = i < 4 ? 4 : 6;
            require(bufferreaderGather(&reader, needed) == (i + 1U == needed),
                    "incremental gather returned the wrong completion state");
            require(bufferreaderHeaderLength(&reader) == i + 1U && memoryEqual(header, wire, i + 1U) &&
                        header[i + 1U] == 0 && bufferreaderEntryCount(&reader) == 0 &&
                        bufferreaderLength(&reader) == i + 1U && bufferreaderCharge(&reader) == 0,
                    "incremental gather lost cached progress or retained exhausted input");
        }
        bufferreaderDestroy(&reader);
    }
}

static void testBufferReaderGatherNoop(buffer_pool_t *pool)
{
    uint8_t         header[5] = {0};
    buffer_reader_t reader;
    bufferreaderInit(&reader, pool, header, sizeof(header));
    sbuf_t      *source = readerTestPush(&reader, streamTestBytes(pool, "abcdhead", 8));
    const size_t charge = bufferreaderCharge(&reader);
    require(bufferreaderGather(&reader, 0) && bufferreaderHeaderLength(&reader) == 0 &&
                bufferreaderLength(&reader) == 8 && bufferreaderEntryCount(&reader) == 1 &&
                bufferreaderCharge(&reader) == charge && bufferreaderHeadLength(&reader) == 0,
            "zero prefix request changed input ownership");
    require(bufferreaderGather(&reader, 4), "no-op fixture could not cache its header");
    sbuf_t      *empty         = readerTestPush(&reader, streamTestBytes(pool, "", 0));
    sbuf_t      *tail          = readerTestPush(&reader, streamTestBytes(pool, "tail", 4));
    const size_t queued_charge = bufferreaderCharge(&reader);
    require(bufferreaderGather(&reader, 4) && bufferreaderGather(&reader, 1) && bufferreaderGather(&reader, 0),
            "cached prefix did not satisfy an equal or earlier parser checkpoint");
    require(bufferreaderHeaderLength(&reader) == 4 && memoryEqual(header, "abcd", sizeof(header)) &&
                bufferreaderLength(&reader) == 12 && bufferreaderEntryCount(&reader) == 3 &&
                bufferreaderHeadLength(&reader) == 4 && bufferreaderCharge(&reader) == queued_charge,
            "satisfied gather changed cached bytes or input accounting");
    sbuf_t *body = bufferreaderTakeBody(&reader, 4);
    require(body == source, "satisfied gather replaced its active head");
    streamCheckBytes(pool, body, "head", 4);
    body = bufferreaderTakeChunk(&reader);
    require(body == empty, "satisfied gather consumed an empty queued entry");
    streamCheckBytes(pool, body, "", 0);
    body = bufferreaderTakeChunk(&reader);
    require(body == tail, "satisfied gather replaced queued input");
    streamCheckBytes(pool, body, "tail", 4);
    bufferreaderDestroy(&reader);
}

static void testBufferReaderRetainedStorage(buffer_pool_t *pool)
{
    uint8_t         header[1];
    buffer_reader_t reader;
    bufferreaderInit(&reader, pool, header, sizeof(header));
    sbuf_t *head = readerTestPush(&reader, streamTestBytes(pool, "Hab", 3));
    require(bufferreaderGather(&reader, 1), "retention fixture could not activate its head");
    bufferreaderConsumeHeader(&reader);
    readerTestPush(&reader, streamTestBytes(pool, "cd", 2));
    const size_t charge = bufferreaderCharge(&reader);
    require(bufferreaderSettle(&reader, charge) && bufferreaderHeadLength(&reader) == 2 &&
                bufferreaderEntryCount(&reader) == 2 && bufferreaderCharge(&reader) == charge,
            "settling within the exact limits changed storage");
    require(bufferreaderSettle(&reader, charge - 1U) && bufferreaderHeadLength(&reader) == 4 &&
                bufferreaderEntryCount(&reader) == 1,
            "charge pressure did not combine input");
    sbuf_t *body = bufferreaderTakeChunk(&reader);
    require(body == head, "charge pressure discarded existing append room");
    streamCheckBytes(pool, body, "abcd", 4);
    bufferreaderDestroy(&reader);

    buffer_pool_fit_t fit;
    require(bufferpoolQueryBestFit(pool, 4, bufferpoolGetLargeBufferPadding(pool), &fit),
            "retained-storage fixture geometry failed");
    for (unsigned fits = 0; fits < 2; ++fits)
    {
        bufferreaderInit(&reader, pool, header, sizeof(header));
        sbuf_t *input = bufferpoolGetLargeBuffer(pool);
        sbufSetLength(input, 5);
        sbufWrite(input, "Hbody", 5);
        head = readerTestPush(&reader, input);
        require(bufferreaderGather(&reader, 1), "oversized-head fixture could not gather metadata");
        bufferreaderConsumeHeader(&reader);
        require(bufferreaderSettle(&reader, fit.allocation_charge - ! fits) == (fits != 0),
                "retained storage accepted an impossible budget or refused fitting storage");
        require(bufferreaderLength(&reader) == 4 && bufferreaderEntryCount(&reader) == 1,
                "settlement changed logical bytes or input ownership");
        if (fits)
        {
            require(bufferreaderCharge(&reader) <= fit.allocation_charge, "oversized head did not compact");
            body = bufferreaderTakeChunk(&reader);
            require(body != head, "oversized retained allocation was not replaced");
            streamCheckBytes(pool, body, "body", 4);
        }
        else
            require(bufferreaderCharge(&reader) == sbufGetQueueCharge(head) && sbufGetLength(head) == 4,
                    "settlement refusal consumed retained input");
        bufferreaderDestroy(&reader);
    }

    /* Repeated pressure must reuse assembly room instead of recopying a growing
     * body. Only this allocation-count oracle reads a private reader field. */
    uint8_t expected[12 * 1024];
    for (uint32_t i = 0; i < sizeof(expected); ++i)
        expected[i] = (uint8_t) i;
    bufferreaderInit(&reader, pool, header, sizeof(header));
    unsigned replacements = 0;
    for (uint32_t offset = 0; offset < sizeof(expected); offset += 256)
    {
        sbuf_t *fragment = bufferpoolGetLargeBuffer(pool);
        sbufSetLength(fragment, 256);
        sbufWrite(fragment, expected + offset, 256);
        readerTestPush(&reader, fragment);
        sbuf_t *saved = reader.head;
        require(bufferpoolQueryBestFit(pool, offset + 256U, bufferpoolGetLargeBufferPadding(pool), &fit),
                "fragmented-body fixture geometry failed");
        require(bufferreaderSettle(&reader, fit.allocation_charge), "bounded fragmented body could not compact");
        if (reader.head != NULL && saved != reader.head)
            ++replacements;
        require(bufferreaderEntryCount(&reader) == 1 && bufferreaderLength(&reader) == offset + 256U,
                "growth compaction lost logical bytes or retained fragments");
    }
    require(replacements <= 3, "retained body repeatedly copied its accumulated prefix");
    streamCheckBytes(pool, bufferreaderTakeBody(&reader, sizeof(expected)), expected, sizeof(expected));
    bufferreaderDestroy(&reader);
}

#if WW_HAVE_SPLICE
static void testBufferReaderRetainedSplice(buffer_pool_t *pool)
{
    for (unsigned mode = 1; mode <= 2; ++mode)
        for (unsigned fault = 0; fault <= 1; ++fault)
        {
            uint8_t         header[1];
            buffer_reader_t reader;
            bufferreaderInit(&reader, pool, header, sizeof(header));
            readerTestPush(&reader, readerTestInput(pool, (const uint8_t *) "Habc", 4, mode));
            require(bufferreaderGather(&reader, 1), "splice retention fixture could not activate its head");
            bufferreaderConsumeHeader(&reader);
            readerTestPush(&reader, readerTestInput(pool, (const uint8_t *) "def", 3, 1));
            /* Retained empty storage creates real charge pressure while keeping
             * the body split across both splice sources. */
            readerTestPush(&reader, bufferpoolGetLargeBuffer(pool));
            buffer_pool_fit_t fit;
            require(bufferpoolQueryBestFit(pool, 6, bufferpoolGetLargeBufferPadding(pool), &fit),
                    "splice retention fixture geometry failed");
            streamProbe         = true;
            streamTransferFault = fault ? 3 : 0;
            require(bufferreaderSettle(&reader, fit.allocation_charge), "splice retention could not compact");
            streamProbe         = false;
            streamTransferFault = 0;
            require(bufferreaderEntryCount(&reader) == 1, "splice compaction retained multiple entries");
            sbuf_t *body = bufferreaderTakeChunk(&reader);
            require(sbufIsSplice(body) == ! fault,
                    "retained assembly did not preserve pipes or select complete fallback");
            streamCheckBytes(pool, body, "abcdef", 6);
            bufferreaderDestroy(&reader);
        }

    /* Appending to a pipe can exceed the charge cap even when ordinary storage
     * fits, because ordinary and splice padding can differ. */
    pool_fixture_t  fixture = poolFixtureCreate(256, 128, 0, 0);
    uint8_t         header[1];
    buffer_reader_t reader;
    bufferreaderInit(&reader, fixture.pool, header, sizeof(header));
    uint8_t wire[81] = {0};
    sbuf_t *head     = readerTestPush(&reader, makeSpliceTestBuffer(fixture.pool, NULL, 0, wire, 49));
    require(bufferreaderGather(&reader, 1), "differing-padding fixture could not activate its head");
    bufferreaderConsumeHeader(&reader);
    readerTestPush(&reader, streamTestBytes(fixture.pool, wire + 49, 32));
    buffer_pool_fit_t fit;
    require(bufferpoolQueryBestFit(fixture.pool, 80, 0, &fit) && sbufGetQueueCharge(head) <= fit.allocation_charge,
            "differing splice padding fixture does not fit its initial head");
    require(bufferreaderSettle(&reader, fit.allocation_charge) && bufferreaderCharge(&reader) <= fit.allocation_charge,
            "splice append bypassed the final retained charge limit");
    sbuf_t *body = bufferreaderTakeChunk(&reader);
    require(! sbufIsSplice(body), "pipe charge pressure did not select fitting ordinary storage");
    streamCheckBytes(fixture.pool, body, wire + 1, 80);
    bufferreaderDestroy(&reader);
    poolFixtureDestroy(&fixture);
}

static void testBufferReaderSpliceFallback(buffer_pool_t *pool)
{
    const unsigned faults[] = {1, 3, 5};
    for (size_t i = 0; i < ARRAY_SIZE(faults); ++i)
    {
        uint8_t         header[1];
        buffer_reader_t reader;
        bufferreaderInit(&reader, pool, header, sizeof(header));
        sbuf_t   *source = readerTestPush(&reader, makeSpliceTestBuffer(pool, NULL, 0, (const uint8_t *) "abcdef", 6));
        const int source_fd = sbufSpliceMetadata(source).pipefd[0];
        streamProbe         = true;
        streamTransferFault = faults[i];
        streamReadBytes     = 0;
        streamSpliceBytes   = 0;
        sbuf_t *body        = bufferreaderTakeBody(&reader, 3);
        streamProbe         = false;
        streamTransferFault = 0;
        const bool fallback = faults[i] != 1;
        require(sbufIsSplice(body) == ! fallback && streamReadBytes == (fallback ? 3U : 0U),
                "extraction fault did not select complete ordinary fallback or preserve the splice path");
        require(streamSpliceBytes == (faults[i] == 5 ? 1U : (fallback ? 0U : 3U)),
                "extraction fault lost short-transfer progress");
        require(bufferreaderHeadLength(&reader) == 3 && bufferreaderLength(&reader) == 3,
                "fallback lost the retained suffix");
        sbuf_t *suffix = bufferreaderTakeBody(&reader, 3);
        require(suffix == source && sbufSpliceMetadata(suffix).pipefd[0] == source_fd,
                "fallback changed source suffix ownership");
        streamCheckBytes(pool, suffix, "def", 3);
        streamCheckBytes(pool, body, "abc", 3);
        bufferreaderDestroy(&reader);
    }

    uint8_t         header[1];
    buffer_reader_t reader;
    bufferreaderInit(&reader, pool, header, sizeof(header));
    readerTestPush(&reader, makeSpliceTestBuffer(pool, NULL, 0, (const uint8_t *) "abcdef", 6));
    test_splice_inventory_hold_t held = testSpliceInventoryHoldAvailable(pool);
    require(bufferpoolGetSpliceBuffer(pool) == NULL, "extraction fixture did not exhaust destination pipes");
    sbuf_t *body = bufferreaderTakeBody(&reader, 3);
    require(! sbufIsSplice(body), "extraction did not fall back after pipe checkout refusal");
    streamCheckBytes(pool, body, "abc", 3);
    streamCheckBytes(pool, bufferreaderTakeBody(&reader, 3), "def", 3);
    bufferreaderDestroy(&reader);
    testSpliceInventoryReleaseHeld(&held);

    /* A contributing splice wrapper selects splice output even when only its
     * resident prefix is requested; its private-pipe suffix remains independent. */
    for (uint32_t pipe_bytes = 0; pipe_bytes <= 4; pipe_bytes += 4)
    {
        bufferreaderInit(&reader, pool, header, sizeof(header));
        readerTestPush(&reader,
                       makeSpliceTestBuffer(pool, (const uint8_t *) "abcd", 4, (const uint8_t *) "PIPE", pipe_bytes));
        body = bufferreaderTakeBody(&reader, 2);
        require(sbufIsSplice(body), "resident-prefix extraction changed wrapper-based representation selection");
        streamCheckBytes(pool, body, "ab", 2);
        streamCheckBytes(pool, bufferreaderTakeBody(&reader, 2 + pipe_bytes), "cdPIPE", 2 + pipe_bytes);
        bufferreaderDestroy(&reader);
    }
}
#endif

static void testBufferReaderStorageContracts(buffer_pool_t *pool)
{
    testCaseSet("buffer reader: extraction, metadata and retained storage");
    testBufferReaderExtractionSplits(pool);
    testBufferReaderZeroAndIdentity(pool);
    testBufferReaderPaddingAndQueuedSuffix(pool);
    testBufferReaderGatherSplits(pool);
    testBufferReaderGatherIncremental(pool);
    testBufferReaderGatherNoop(pool);
    testBufferReaderRetainedStorage(pool);
#if WW_HAVE_SPLICE
    testBufferReaderRetainedSplice(pool);
    testBufferReaderSpliceFallback(pool);
#endif
}
