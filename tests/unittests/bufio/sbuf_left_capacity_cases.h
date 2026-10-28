/*
 * Covers: splice-aware left-capacity repair and exclusive replacement ownership.
 * Setup: Included after splice_stream_cases.h by bufio_contract_test.c; reuses
 * its pool, source pipes and syscall fault probes.
 * Cases: ordinary/splice fast paths, empty payloads, complete prefix/body order,
 * full onward padding, pipe checkout/padding refusal and partial transfer fallback.
 * CTest: waterwall.bufio_contract_unit; waterwall.bufio_contract_no_splice_unit.
 */

static void leftCapacityCheckPayload(buffer_pool_t *pool, sbuf_t *buf, const uint8_t *expected, uint32_t length)
{
    uint8_t actual[32];
    require(length <= sizeof(actual) && sbufGetLength(buf) == length, "left-capacity repair changed payload length");
    sbufReadRangeToMemory(buf, actual, length);
    require(memoryEqual(actual, expected, length), "left-capacity repair changed payload bytes or order");
    bufferpoolReuseBuffer(pool, buf);
}

static void testOrdinaryLeftCapacity(void)
{
    pool_fixture_t fixture = poolFixtureCreate(1024, 128, 64, 32);
    const uint16_t needs[] = {0, 32, 33, 97};
    const uint8_t  wire[]  = "payload";
    for (unsigned empty = 0; empty < 2; ++empty)
        for (size_t i = 0; i < ARRAY_SIZE(needs); ++i)
        {
            const uint32_t length = empty ? 0 : sizeof(wire) - 1;
            sbuf_t        *source = bufferpoolGetSmallBuffer(fixture.pool);
            sbufSetLength(source, length);
            memoryCopy(sbufGetMutablePtr(source), wire, length);
            uint32_t before[4], after[4];
            bufferpoolCachedTierCountsForTest(fixture.pool, &before[0], &before[1], &before[2], &before[3]);
            sbuf_t *result = sbufEnsureLeftCapacity(fixture.pool, source, needs[i]);
            bufferpoolCachedTierCountsForTest(fixture.pool, &after[0], &after[1], &after[2], &after[3]);
            require(! sbufIsSplice(result) && sbufGetLeftCapacity(result) >= needs[i],
                    "ordinary left-capacity repair lost headroom or changed representation");
            if (needs[i] <= 32)
                require(result == source && result->curpos == 32 && memoryEqual(before, after, sizeof(before)),
                        "sufficient ordinary headroom changed the buffer or pool caches");
            else
            {
                require(result != source && sbufGetLeftCapacity(result) >= max(64U, needs[i]),
                        "ordinary replacement lost full onward padding");
                sbuf_t *recycled = bufferpoolGetSmallBuffer(fixture.pool);
                sbuf_t *second   = bufferpoolGetSmallBuffer(fixture.pool);
                require(recycled == source && second != source && sbufGetLength(recycled) == 0,
                        "ordinary source was not recycled exactly once");
                bufferpoolReuseBuffer(fixture.pool, recycled);
                bufferpoolReuseBuffer(fixture.pool, second);
            }
            leftCapacityCheckPayload(fixture.pool, result, wire, length);
        }
    poolFixtureDestroy(&fixture);
}

#if WW_HAVE_SPLICE
static void testSpliceLeftCapacity(void)
{
    pool_fixture_t fixture = poolFixtureCreate(1024, 128, 64, 64);
    const uint8_t  wire[]  = "prefix!body";
    for (uint32_t prefix = 0; prefix <= 7; prefix += 7)
        for (uint32_t body = 0; body <= 4; body += 4)
            for (unsigned mode = 0; mode < 3; ++mode)
            {
                sbuf_t                        *source          = testSpliceSourceBuffer(32, body);
                const splice_buffer_metadata_t source_metadata = sbufSpliceMetadata(source);
                writeSpliceTestBody(source_metadata.pipefd[1], wire + prefix, body);
                source->capacity = source->l_pad + body;
                sbufSetLength(source, body);
                sbufShiftLeft(source, prefix);
                memoryCopy(sbufGetMutablePtr(source), wire, prefix);
                const uint16_t need   = mode == 0 ? 0 : mode == 1 ? (uint16_t) source->curpos : 33;
                const uint32_t cursor = source->curpos;
                uint32_t       before[4], after[4];
                bufferpoolCachedTierCountsForTest(fixture.pool, &before[0], &before[1], &before[2], &before[3]);
                streamProbe     = true;
                streamReadBytes = streamSpliceBytes = 0;
                sbuf_t *result                      = sbufEnsureLeftCapacity(fixture.pool, source, need);
                streamProbe                         = false;
                bufferpoolCachedTierCountsForTest(fixture.pool, &after[0], &after[1], &after[2], &after[3]);
                require(sbufIsSplice(result) && sbufGetLeftCapacity(result) >= need && streamReadBytes == 0,
                        "splice headroom repair materialized available pipe storage or lost padding");
                if (mode != 2)
                    require(result == source && result->curpos == cursor && streamSpliceBytes == 0 &&
                                memoryEqual(before, after, sizeof(before)),
                            "sufficient splice headroom changed the buffer, pipe or pool caches");
                else
                {
                    require(result != source && sbufGetLeftCapacity(result) >= 64 && streamSpliceBytes == body,
                            "splice replacement lost onward padding or private-body bytes");
                    require(fcntl(source_metadata.pipefd[0], F_GETFD) < 0 && errno == EBADF &&
                                fcntl(source_metadata.pipefd[1], F_GETFD) < 0 && errno == EBADF,
                            "splice replacement retained its consumed unmanaged source pipe");
                }
                leftCapacityCheckPayload(fixture.pool, result, wire, prefix + body);
            }
    poolFixtureDestroy(&fixture);
}

static void testLeftCapacityTransferFallback(void)
{
    pool_fixture_t fixture  = poolFixtureCreate(1024, 128, 64, 64);
    const uint8_t  wire[]   = "prefix!abcdef";
    const unsigned faults[] = {1, 3, 5};
    for (size_t i = 0; i < ARRAY_SIZE(faults); ++i)
    {
        sbuf_t                        *source   = makeSpliceTestBuffer(fixture.pool, wire, 7, wire + 7, 6);
        const splice_buffer_metadata_t metadata = sbufSpliceMetadata(source);
        streamProbe                             = true;
        streamTransferFault                     = faults[i];
        streamReadBytes = streamSpliceBytes = 0;
        sbuf_t *result                      = sbufEnsureLeftCapacity(fixture.pool, source, 58);
        streamProbe                         = false;
        streamTransferFault                 = 0;
        const bool fallback                 = faults[i] != 1;
        require(sbufIsSplice(result) == ! fallback && streamReadBytes == (fallback ? 13U : 0U) &&
                    sbufGetLeftCapacity(result) >= 64,
                "left-capacity transfer refusal lost complete fallback or onward headroom");
        require(streamSpliceBytes == (faults[i] == 5 ? 1U
                                      : fallback     ? 0U
                                                     : 6U),
                "left-capacity transfer lost partial progress or EINTR handling");
        sbuf_t *recycled = bufferpoolGetSpliceBuffer(fixture.pool);
        sbuf_t *second   = bufferpoolGetSpliceBuffer(fixture.pool);
        require(recycled == source && second != source && sbufGetLength(recycled) == 0 &&
                    sbufSpliceIsReusable(recycled) && sbufSpliceMetadata(recycled).pipefd[0] == metadata.pipefd[0],
                "splice source was not recycled exactly once with its empty pipe");
        bufferpoolReuseBuffer(fixture.pool, recycled);
        bufferpoolReuseBuffer(fixture.pool, second);
        leftCapacityCheckPayload(fixture.pool, result, wire, sizeof(wire) - 1);
    }
    poolFixtureDestroy(&fixture);
}

static void testLeftCapacityDestinationRefusal(void)
{
    const uint8_t wire[] = "prefix!body";
    for (unsigned insufficient_padding = 0; insufficient_padding < 2; ++insufficient_padding)
    {
        pool_fixture_t               fixture = poolFixtureCreate(1024, 128, insufficient_padding ? 192 : 64, 64);
        sbuf_t                      *source  = makeSpliceTestBuffer(fixture.pool, wire, 7, wire + 7, 4);
        test_splice_inventory_hold_t held    = {0};
        if (! insufficient_padding)
        {
            held = testSpliceInventoryHoldAvailable(fixture.pool);
            require(bufferpoolGetSpliceBuffer(fixture.pool) == NULL,
                    "left-capacity fixture did not exhaust destination pipes");
        }
        sbuf_t *result = sbufEnsureLeftCapacity(fixture.pool, source, 58);
        require(! sbufIsSplice(result) && sbufGetLeftCapacity(result) >= bufferpoolGetLargeBufferPadding(fixture.pool),
                "unavailable or underpadded splice destination did not select full ordinary storage");
        sbuf_t *recycled = bufferpoolGetSpliceBuffer(fixture.pool);
        require(recycled == source && sbufGetLength(recycled) == 0 && sbufSpliceIsReusable(recycled),
                "destination refusal failed to return the consumed source pipe");
        bufferpoolReuseBuffer(fixture.pool, recycled);
        leftCapacityCheckPayload(fixture.pool, result, wire, sizeof(wire) - 1);
        testSpliceInventoryReleaseHeld(&held);
        poolFixtureDestroy(&fixture);
    }
}
#endif

static void testSbufLeftCapacityContracts(void)
{
    testOrdinaryLeftCapacity();
#if WW_HAVE_SPLICE
    testSpliceLeftCapacity();
    testLeftCapacityTransferFallback();
    testLeftCapacityDestinationRefusal();
#endif
}
