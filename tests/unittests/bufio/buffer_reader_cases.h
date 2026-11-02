/*
 * Covers: staged header/body accounting, bounded admission, storage settlement,
 * passthrough/fallback transfer and cleanup for ordinary and private-pipe input.
 * Setup: Existing bufio pool/storage fixtures on one registered owner worker.
 * CTest: waterwall.bufio_contract_unit; waterwall.bufio_contract_no_splice_unit.
 */
#include "buffer_reader.h"
#include "fixtures/worker_registry_fixture.h"

static void testBufferReaderFragments(buffer_pool_t *pool)
{
    testCaseSet("buffer reader: partial headers, exact bodies and zero datagrams");
    for (unsigned mode = 0; mode < (WW_HAVE_SPLICE ? 3U : 1U); ++mode)
    {
        uint8_t         header[4] = {0};
        buffer_reader_t reader;
        bufferreaderInit(&reader, pool, header, sizeof(header));
        require(! bufferreaderGather(&reader, 4), "empty reader completed a missing header");
        sbuf_t *input = streamTestBytes(pool, "ab", 2);
        require(bufferreaderTryPush(&reader, &input, 9), "initial header fragment was refused");
        require(! bufferreaderGather(&reader, 4) && bufferreaderHeaderLength(&reader) == 2 &&
                    bufferreaderLength(&reader) == 2 && bufferreaderBodyBytes(&reader) == 0 &&
                    bufferreaderCharge(&reader) == 0 && memoryEqual(bufferreaderHeader(&reader), "ab", 2),
                "partial gather lost progress or stopped charging cached bytes");
        input = readerTestInput(pool, (const uint8_t *) "cdBODYx", 7, mode);
        require(bufferreaderTryPush(&reader, &input, 9) && bufferreaderGather(&reader, 4),
                "mixed input did not complete its header");
        require(bufferreaderLength(&reader) == 9 && bufferreaderBodyBytes(&reader) == 5 &&
                    bufferreaderBodyReady(&reader, 5) && ! bufferreaderBodyReady(&reader, 6) &&
                    memoryEqual(bufferreaderHeader(&reader), "abcd", 4),
                "completed gather changed header/body accounting");
        streamCheckBytes(pool, bufferreaderTakeBody(&reader, 4), "BODY", 4);
        require(bufferreaderLength(&reader) == 1 && bufferreaderHeaderLength(&reader) == 0 &&
                    bufferreaderGather(&reader, 1) && bufferreaderHeader(&reader)[0] == 'x',
                "body extraction failed to reset the header or preserve the following frame");
        streamCheckBytes(pool, bufferreaderTakeBody(&reader, 0), "", 0);
        require(bufferreaderLength(&reader) == 0 && bufferreaderHeaderLength(&reader) == 0 &&
                    bufferreaderEntryCount(&reader) == 0,
                "empty datagram retained its header or input storage");
        bufferreaderDestroy(&reader);
    }
}

static void testBufferReaderAdmissionAndChunks(buffer_pool_t *pool)
{
    testCaseSet("buffer reader: inclusive admission and caller ownership on refusal");
    uint8_t         header[4];
    buffer_reader_t reader;
    bufferreaderInit(&reader, pool, header, sizeof(header));
    sbuf_t *input = streamTestBytes(pool, "ab", 2);
    require(bufferreaderTryPush(&reader, &input, 5) && ! bufferreaderGather(&reader, 4),
            "admission fixture did not cache its partial header");
    input                 = streamTestBytes(pool, "cdef", 4);
    sbuf_t *const refused = input;
    require(! bufferreaderTryPush(&reader, &input, 5) && input == refused && bufferreaderLength(&reader) == 2 &&
                bufferreaderHeaderLength(&reader) == 2 && bufferreaderEntryCount(&reader) == 0 &&
                memoryEqual(bufferreaderHeader(&reader), "ab", 2),
            "refusal consumed caller input or changed retained state");
    streamCheckBytes(pool, input, "cdef", 4);
    input = streamTestBytes(pool, "cde", 3);
    require(bufferreaderTryPush(&reader, &input, 5) && bufferreaderLength(&reader) == 5,
            "exact inclusive limit was refused");
    input = streamTestBytes(pool, "", 0);
    require(! bufferreaderTryPush(&reader, &input, 4) && bufferreaderEntryCount(&reader) == 1,
            "lowered limit admitted input while existing bytes already exceeded it");
    require(bufferreaderTryPush(&reader, &input, 5) && bufferreaderEntryCount(&reader) == 2,
            "empty input at the exact limit did not transfer ownership");
    bufferreaderConsumeHeader(&reader);
    require(bufferreaderLength(&reader) == 3 && bufferreaderHeaderLength(&reader) == 0,
            "consuming metadata changed unread body accounting");
    streamCheckBytes(pool, bufferreaderTakeChunk(&reader), "cde", 3);
    streamCheckBytes(pool, bufferreaderTakeChunk(&reader), "", 0);
    require(bufferreaderTakeChunk(&reader) == NULL && bufferreaderLength(&reader) == 0 &&
                bufferreaderCharge(&reader) == 0,
            "chunk transfer retained input or lost the empty chunk");
    bufferreaderDestroy(&reader);
}

static void testBufferReaderRetention(buffer_pool_t *pool)
{
    testCaseSet("buffer reader: compact retained storage without changing cached metadata or FIFO");
    buffer_pool_fit_t fit;
    require(bufferpoolQueryBestFit(pool, 4, bufferpoolGetLargeBufferPadding(pool), &fit),
            "reader retention fixture has invalid pool geometry");
    for (unsigned mode = 0; mode < (WW_HAVE_SPLICE ? 2U : 1U); ++mode)
    {
        uint8_t         header[2];
        buffer_reader_t reader;
        bufferreaderInit(&reader, pool, header, sizeof(header));
        sbuf_t *input = bufferpoolGetBestFit(pool, 128U * 1024U, bufferpoolGetLargeBufferPadding(pool));
        sbufSetLength(input, 4);
        sbufWrite(input, "abCD", 4);
        require(bufferreaderTryPush(&reader, &input, 6) && bufferreaderGather(&reader, 2),
                "reader retention fixture could not gather metadata");
        input = readerTestInput(pool, (const uint8_t *) "EF", 2, mode);
        require(bufferreaderTryPush(&reader, &input, 6), "reader retention fixture refused its tail");
        require(bufferreaderSettle(&reader, fit.allocation_charge, 1) &&
                    bufferreaderCharge(&reader) <= fit.allocation_charge && bufferreaderEntryCount(&reader) == 1 &&
                    bufferreaderLength(&reader) == 6 && bufferreaderBodyBytes(&reader) == 4 &&
                    memoryEqual(bufferreaderHeader(&reader), "ab", 2),
                "settlement lost cached bytes, accounting or the retained-storage bound");
        streamCheckBytes(pool, bufferreaderTakeBody(&reader, 4), "CDEF", 4);
        require(bufferreaderSettle(&reader, 0, 1), "empty retention failed a zero charge limit");

        input = bufferpoolGetLargeBuffer(pool);
        sbufSetLength(input, 4);
        sbufWrite(input, "abCD", 4);
        require(bufferreaderTryPush(&reader, &input, 4) && bufferreaderGather(&reader, 2),
                "settlement refusal fixture did not retain its body");
        require(! bufferreaderSettle(&reader, fit.allocation_charge - 1U, 1) && bufferreaderLength(&reader) == 4 &&
                    bufferreaderHeaderLength(&reader) == 2,
                "impossible retention geometry was accepted or lost logical bytes");
        bufferreaderDestroy(&reader);
    }
}

static void testBufferReaderQueueTransfer(buffer_pool_t *pool)
{
    testCaseSet("buffer reader: fallback restores inspected bytes and passthrough omits consumed metadata");
    for (unsigned mode = 0; mode < (WW_HAVE_SPLICE ? 3U : 1U); ++mode)
        for (unsigned restore = 0; restore < 2; ++restore)
        {
            uint8_t         header[4];
            buffer_reader_t reader;
            bufferreaderInit(&reader, pool, header, sizeof(header));
            sbuf_t *input = readerTestInput(pool, (const uint8_t *) "HEADbody", 8, mode);
            require(bufferreaderTryPush(&reader, &input, 12), "queue transfer refused the initial input");
            input = streamTestBytes(pool, "tail", 4);
            require(bufferreaderTryPush(&reader, &input, 12) && bufferreaderGather(&reader, 4),
                    "queue transfer failed to inspect the prefix");
            if (! restore)
                bufferreaderConsumeHeader(&reader);
            buffer_queue_t destination;
            require(bufferqueueInit(&destination, 8), "queue transfer destination could not initialize");
            const uint32_t expected_bytes = restore ? 12 : 8;
            const char    *expected       = restore ? "HEADbodytail" : "bodytail";
            require(bufferreaderMoveToQueue(&reader, &destination, restore != 0) && bufferreaderLength(&reader) == 0 &&
                        bufferreaderHeaderLength(&reader) == 0 && bufferreaderCharge(&reader) == 0 &&
                        bufferreaderEntryCount(&reader) == 0 && bufferqueueGetBufLen(&destination) == expected_bytes,
                    "queue transfer lost bytes or left multiple input owners");
            buffer_budget_t budget;
            bufferbudgetInit(&budget,
                             (buffer_budget_cost_t) {expected_bytes,
                                                     bufferqueueGetCharge(&destination),
                                                     bufferqueueGetBufCount(&destination)});
            require(bufferqueueTryAttachBudget(&destination, &budget),
                    "transferred input could not attach its independent exact output budget");
            input = streamTestBytes(pool, "NEW", 3);
            require(bufferreaderTryPush(&reader, &input, 3), "emptied reader could not accept independent input");
            bufferreaderDestroy(&reader);
            require(bufferbudgetGetUsage(&budget).bytes == expected_bytes,
                    "reader cleanup released transferred destination accounting");
            uint32_t offset = 0;
            while ((input = bufferqueuePopFront(&destination)) != NULL)
            {
                const uint32_t bytes = sbufGetLength(input);
                require(bytes <= expected_bytes - offset, "queue transfer duplicated bytes");
                streamCheckBytes(pool, input, expected + offset, bytes);
                offset += bytes;
            }
            require(offset == expected_bytes, "queue transfer dropped bytes");
            bufferbudgetAssertEmpty(&budget);
            bufferqueueDestroy(&destination);
        }
}

static void testBufferReaderCleanup(buffer_pool_t *pool)
{
    testCaseSet("buffer reader: clear preserves bindings and destroy releases queued input");
    uint8_t         header[4];
    buffer_reader_t reader;
    bufferreaderInit(&reader, pool, header, sizeof(header));
    for (unsigned pass = 0; pass < 2; ++pass)
    {
        sbuf_t *input = readerTestInput(pool, (const uint8_t *) "HEADbody", 8, WW_HAVE_SPLICE ? 1 : 0);
        require(bufferreaderTryPush(&reader, &input, 12) && bufferreaderGather(&reader, 4),
                "cleanup fixture could not retain its head");
        input = streamTestBytes(pool, "tail", 4);
        require(bufferreaderTryPush(&reader, &input, 12), "cleanup fixture could not retain its queued tail");
        bufferreaderClear(&reader);
        require(bufferreaderLength(&reader) == 0 && bufferreaderHeaderLength(&reader) == 0 &&
                    bufferreaderEntryCount(&reader) == 0 && bufferreaderCharge(&reader) == 0 &&
                    bufferreaderHeader(&reader) == header,
                "clear lost its binding or retained owned storage");
    }
    sbuf_t *input = readerTestInput(pool, (const uint8_t *) "pending", 7, WW_HAVE_SPLICE ? 1 : 0);
    require(bufferreaderTryPush(&reader, &input, 7), "destroy fixture could not retain its queued input");
    bufferreaderDestroy(&reader);
    require(bufferreaderHeader(&reader) == NULL && bufferreaderLength(&reader) == 0 &&
                bufferreaderCharge(&reader) == 0 && bufferreaderEntryCount(&reader) == 0,
            "destroy retained its binding or owned input");
    bufferreaderInit(&reader, pool, header, sizeof(header));
    input = streamTestBytes(pool, "again", 5);
    require(bufferreaderTryPush(&reader, &input, 5), "destroyed reader could not be initialized again");
    streamCheckBytes(pool, bufferreaderTakeChunk(&reader), "again", 5);
    bufferreaderDestroy(&reader);
}

static void testBufferReaderContracts(void)
{
    pool_fixture_t         fixture = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 64);
    test_worker_registry_t registry;
    const uint32_t         saved_workers_count = GSTATE.workers_count;
    buffer_pool_t        **saved_pools         = GSTATE.shortcut_buffer_pools;
    buffer_pool_t         *pools[]             = {fixture.pool};
    GSTATE.workers_count                       = 1;
    GSTATE.shortcut_buffer_pools               = pools;
    testWorkerRegistryInstall(&registry);
    registry.slots[0].buffer_pool = fixture.pool;
    testWorkerBindWID(0);
    testBufferReaderStorageContracts(fixture.pool);
    testBufferReaderFragments(fixture.pool);
    testBufferReaderAdmissionAndChunks(fixture.pool);
    testBufferReaderRetention(fixture.pool);
    testBufferReaderQueueTransfer(fixture.pool);
    testBufferReaderCleanup(fixture.pool);
    workerUnbindCurrentThread();
    testWorkerRegistryRestore(&registry);
    GSTATE.workers_count         = saved_workers_count;
    GSTATE.shortcut_buffer_pools = saved_pools;
    poolFixtureDestroy(&fixture);
}
