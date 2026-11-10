/* BufferStream accessor, retention and ordinary-admission cases for bufio_contract_test.c.
 * Uses its owner-local pool fixture; every retained/extracted buffer is settled
 * before fixture teardown. Runs in the splice and no-splice contract targets. */

static void testBufferStreamAccessors(void)
{
    pool_fixture_t  fixture = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 64);
    buffer_stream_t stream;
    bufferstreamInitEmpty(&stream, fixture.pool, 16);
    require(bufferstreamGetEntryCount(&stream) == 0 && bufferstreamGetCharge(&stream) == 0 &&
                bufferstreamGetHeadLength(&stream) == 0 && bufferstreamIsEmpty(&stream),
            "lazy stream did not start empty");
    bufferstreamDestroy(&stream);
    bufferstreamInitEmpty(&stream, fixture.pool, 16);

    sbuf_t      *empty        = makePooledBuffer(fixture.pool, false, 0, 0, 0);
    const size_t small_charge = sbufGetAllocationCharge(empty);
    bufferstreamPush(&stream, empty);
    require(bufferstreamIsEmpty(&stream) && bufferstreamGetEntryCount(&stream) == 1 &&
                bufferstreamGetCharge(&stream) == small_charge && bufferstreamGetHeadLength(&stream) == 0,
            "retained empty entry lost its storage charge");

    bufferstreamPush(&stream, makePooledBuffer(fixture.pool, false, 8, 0, 0x20));
    bufferstreamPush(&stream, makePooledBuffer(fixture.pool, false, 4, 0, 0x40));
    require(bufferstreamGetEntryCount(&stream) == 1 && bufferstreamGetHeadLength(&stream) == 12 &&
                bufferstreamGetCharge(&stream) == small_charge,
            "coalesced input counted recycled storage");

    sbuf_t      *large        = makePooledBuffer(fixture.pool, true, 8000, 0, 0x60);
    const size_t large_charge = sbufGetAllocationCharge(large);
    bufferstreamPush(&stream, large);
    require(bufferstreamGetEntryCount(&stream) == 2 && bufferstreamGetHeadLength(&stream) == 12 &&
                bufferstreamGetCharge(&stream) == small_charge + large_charge,
            "separate input lost retained storage accounting");

    sbuf_t *read = bufferstreamReadExact(&stream, 5);
    requirePatternRange(read, 0, 5, 0x20, "split exact read changed bytes");
    require(sbufGetHeadroom(read) == 48, "lazy initialization lost the exact-read padding budget");
    bufferpoolReuseBuffer(fixture.pool, read);
    require(bufferstreamGetHeadLength(&stream) == 7 && bufferstreamGetEntryCount(&stream) == 2 &&
                bufferstreamGetCharge(&stream) == small_charge + large_charge,
            "partial read released retained backing storage");

    read = bufferpoolGetSmallBuffer(fixture.pool);
    bufferstreamMoveExactBytesTo(&stream, read, 7);
    requirePatternRange(read, 0, 3, 0x25, "exact move changed first entry suffix");
    requirePatternRange(read, 3, 4, 0x40, "exact move changed coalesced suffix");
    bufferpoolReuseBuffer(fixture.pool, read);
    require(bufferstreamGetHeadLength(&stream) == 8000 && bufferstreamGetEntryCount(&stream) == 1 &&
                bufferstreamGetCharge(&stream) == large_charge,
            "complete move did not release first entry charge");

    read = bufferstreamReadAtLeast(&stream, 8000);
    requirePatternRange(read, 0, 8000, 0x60, "at-least read changed remaining bytes");
    bufferpoolReuseBuffer(fixture.pool, read);
    require(bufferstreamGetCharge(&stream) == 0 && bufferstreamGetEntryCount(&stream) == 0 &&
                bufferstreamGetHeadLength(&stream) == 0,
            "complete read retained accounting");

    bufferstreamPush(&stream, makePooledBuffer(fixture.pool, false, 2, 0, 0x80));
    bufferstreamPush(&stream, makePooledBuffer(fixture.pool, false, 0, 0, 0));
    read = bufferstreamFullRead(&stream);
    bufferpoolReuseBuffer(fixture.pool, read);
    require(bufferstreamIsEmpty(&stream) && bufferstreamGetCharge(&stream) == small_charge &&
                bufferstreamGetEntryCount(&stream) == 1 && bufferstreamGetHeadLength(&stream) == 0,
            "logical drain hid the retained trailing empty entry");
    bufferstreamEmpty(&stream);
    require(bufferstreamGetCharge(&stream) == 0 && bufferstreamGetEntryCount(&stream) == 0,
            "empty did not settle retained storage");
    bufferstreamDestroy(&stream);
    poolFixtureDestroy(&fixture);
}

static void testBufferStreamSettleRetained(void)
{
    pool_fixture_t  fixture = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 64);
    buffer_stream_t stream;
    bufferstreamInitEmpty(&stream, fixture.pool, 16);
    require(bufferstreamSettleRetained(&stream, 0), "lazy empty retention settlement failed");

    bufferstreamPush(&stream, makePooledBuffer(fixture.pool, false, 0, 0, 0));
    bufferstreamPush(&stream, makePooledBuffer(fixture.pool, true, 0, 0, 0));
    bufferstreamPush(&stream, makePooledBuffer(fixture.pool, false, 0, 0, 0));
    require(bufferstreamGetEntryCount(&stream) == 3 && bufferstreamGetCharge(&stream) > 0,
            "empty retention setup did not retain separate allocations");
    require(bufferstreamSettleRetained(&stream, SIZE_MAX), "empty retention settlement failed");
    require(bufferstreamIsEmpty(&stream) && bufferstreamGetEntryCount(&stream) == 0 &&
                bufferstreamGetCharge(&stream) == 0,
            "empty retention settlement kept empty allocations below the limits");

    sbuf_t        *original        = makePooledBuffer(fixture.pool, false, 20, 7, 0x30);
    const size_t   original_cursor = sbufGetHeadroom(original);
    const size_t   original_charge = sbufGetAllocationCharge(original);
    bufferstreamPush(&stream, original);
    require(bufferstreamSettleRetained(&stream, original_charge), "exact retention limits were refused");
    require(bufferstreamSettleRetained(&stream, 0), "best-fit charge floor was refused");
    require(*bs_doublequeue_t_front(&stream.q) == original &&
                sbufGetHeadroom(*bs_doublequeue_t_front(&stream.q)) == original_cursor &&
                bufferstreamGetEntryCount(&stream) == 1 && bufferstreamGetCharge(&stream) == original_charge,
            "settlement copied input already within its effective limits");
    sbuf_t *read = bufferstreamFullRead(&stream);
    requirePatternRange(read, 0, 20, 0x30, "no-op settlement changed payload");
    bufferpoolReuseBuffer(fixture.pool, read);

    /* Exhaust each tail so Push cannot coalesce the one-byte fragments. */
    sbuf_t *fragments[1025];
    for (size_t i = 0; i < ARRAY_SIZE(fragments); ++i)
    {
        fragments[i] = makePooledBuffer(fixture.pool, false, 1, kTestSmallBufferSize - 1, (uint8_t) (0x50 + i));
        bufferstreamPush(&stream, fragments[i]);
    }
    require(bufferstreamGetEntryCount(&stream) == ARRAY_SIZE(fragments), "fragment retention setup coalesced input");
    require(bufferstreamSettleRetained(&stream, bufferstreamGetCharge(&stream)),
            "exact fragment retention limits were refused");
    size_t at = 0;
    c_foreach(entry, bs_doublequeue_t, stream.q)
    {
        require(at < ARRAY_SIZE(fragments) && *entry.ref == fragments[at++],
                "settlement replaced an entry at the exact limits");
    }
    require(at == ARRAY_SIZE(fragments), "settlement changed the exact-limit entry count");
    require(bufferstreamSettleRetained(&stream, original_charge), "charge-pressure retention settlement failed");
    require(bufferstreamGetEntryCount(&stream) == 1 && bufferstreamGetLength(&stream) == ARRAY_SIZE(fragments),
            "charge pressure did not combine tiny fragments");
    read = bufferstreamFullRead(&stream);
    requirePatternRange(read, 0, ARRAY_SIZE(fragments), 0x50, "charge-pressure settlement changed FIFO bytes");
    require(sbufGetHeadroom(read) == 64, "charge-pressure settlement spent left padding");
    bufferpoolReuseBuffer(fixture.pool, read);
    bufferstreamDestroy(&stream);
    poolFixtureDestroy(&fixture);
}

static void testBufferStreamInspectionBoundaries(void)
{
    static const struct
    {
        const char *bytes;
        bool        has_crlf;
        size_t      crlf_at;
        bool        has_double_crlf;
        size_t      double_crlf_end;
    } cases[] = {
        {"", false, 0, false, 0},
        {"\r", false, 0, false, 0},
        {"line\r\nrest", true, 4, false, 0},
        {"a\r\r\n\r\nz", true, 2, true, 6},
        {"x\r\nx\r\n", true, 1, false, 0},
        {"a\r\n\r\nz", true, 1, true, 5},
        {"\r\n\r\n", true, 0, true, 4},
        {"\r\n\n\r\n", true, 0, false, 0},
    };
    pool_fixture_t fixture = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 64);
    for (size_t test = 0; test < ARRAY_SIZE(cases); ++test)
    {
        buffer_stream_t stream = bufferstreamCreate(fixture.pool, 0);
        const size_t    length = strlen(cases[test].bytes);
        /* Every byte occupies a separate, consumed allocation. Interleaved
         * empty entries ensure searches keep delimiter state across both. */
        for (size_t i = 0; i <= length; ++i)
        {
            bufferstreamPush(&stream, makePooledBuffer(fixture.pool, false, 0, kTestSmallBufferSize, 0));
            if (i != length)
                bufferstreamPush(
                    &stream,
                    makePooledBuffer(fixture.pool, false, 1, kTestSmallBufferSize - 1, (uint8_t) cases[test].bytes[i]));
        }
        const size_t charge  = bufferstreamGetCharge(&stream);
        const size_t entries = bufferstreamGetEntryCount(&stream);
        for (size_t i = 0; i < length; ++i)
            require(bufferstreamViewByteAt(&stream, i) == (uint8_t) cases[test].bytes[i],
                    "stream byte view skipped a consumed or empty entry boundary");
        if (length > 2)
        {
            uint8_t copied[32];
            memorySet(copied, 0xa5, sizeof(copied));
            bufferstreamCopyBytesAt(&stream, 1, copied + 1, length - 2);
            require(copied[0] == 0xa5 && copied[length - 1] == 0xa5 &&
                        memoryEqual(copied + 1, cases[test].bytes + 1, length - 2),
                    "stream copy changed its bounds or cross-entry byte order");
        }
        size_t line_end   = SIZE_MAX;
        size_t header_end = SIZE_MAX;
        require(bufferstreamFindCRLF(&stream, &line_end) == cases[test].has_crlf &&
                    line_end == (cases[test].has_crlf ? cases[test].crlf_at : SIZE_MAX),
                "CRLF search changed its split-delimiter offset or no-match output");
        require(bufferstreamFindDoubleCRLF(&stream, &header_end) == cases[test].has_double_crlf &&
                    header_end == (cases[test].has_double_crlf ? cases[test].double_crlf_end : SIZE_MAX),
                "double-CRLF search changed its split-delimiter offset or no-match output");
        require(bufferstreamGetLength(&stream) == length && bufferstreamGetCharge(&stream) == charge &&
                    bufferstreamGetEntryCount(&stream) == entries,
                "stream inspection consumed input or changed retained storage");
        bufferstreamDestroy(&stream);
    }
    poolFixtureDestroy(&fixture);
}

static void testBufferStreamSettleChargeAndPadding(void)
{
    /* The small tier cannot provide the full large-tier padding. The compacted
     * suffix must keep that padding even though exact reads may spend 16 bytes. */
    pool_fixture_t  fixture = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 128, 64);
    buffer_stream_t stream;
    bufferstreamInitEmpty(&stream, fixture.pool, 16);
    bufferstreamPush(&stream, makePooledBuffer(fixture.pool, false, 0, kTestSmallBufferSize, 0));
    sbuf_t *suffix = makeLargePooledBuffer(fixture.pool, 2 * kTestLargeBufferSize, 0, 0x40);
    sbufShiftRight(suffix, 2 * kTestLargeBufferSize - 20);
    bufferstreamPush(&stream, suffix);
    bufferstreamPush(&stream, makePooledBuffer(fixture.pool, false, 0, 0, 0));
    require(bufferstreamGetEntryCount(&stream) == 3 && bufferstreamGetLength(&stream) == 20,
            "charge-pressure setup lost the consumed suffix or empty entries");
    const size_t original_charge = bufferstreamGetCharge(&stream);
    require(bufferstreamSettleRetained(&stream, 0), "charge-pressure retention settlement failed");
    require(bufferstreamGetEntryCount(&stream) == 1 && bufferstreamGetLength(&stream) == 20 &&
                bufferstreamGetCharge(&stream) < original_charge,
            "charge pressure did not release oversized and empty allocations");
    sbuf_t *compacted = *bs_doublequeue_t_front(&stream.q);
    require(sbufGetHeadroom(compacted) == 128 && sbufGetTotalCapacityNoPadding(compacted) == kTestLargeBufferSize,
            "settlement selected storage without full large-tier padding");
    requirePatternRange(compacted, 0, 20, 0x2c, "charge-pressure settlement changed the retained suffix");
    require(bufferstreamSettleRetained(&stream, 0) && *bs_doublequeue_t_front(&stream.q) == compacted,
            "settlement recopied storage already at its best-fit floor");

    sbuf_t *read = bufferstreamReadExact(&stream, 7);
    requirePatternRange(read, 0, 7, 0x2c, "settlement changed a later exact read");
    require(sbufGetHeadroom(read) == 48, "settlement changed the exact-read padding budget");
    bufferpoolReuseBuffer(fixture.pool, read);
    read = bufferstreamFullRead(&stream);
    requirePatternRange(read, 0, 13, 0x33, "settlement changed the suffix after an exact read");
    bufferpoolReuseBuffer(fixture.pool, read);
    bufferstreamDestroy(&stream);
    poolFixtureDestroy(&fixture);
}

#ifndef NDEBUG
static void testBufferStreamRejectsSplice(void)
{
    pool_fixture_t  fixture = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 64);
    for (unsigned test = 0; test < 5; ++test)
    {
        buffer_stream_t stream = bufferstreamCreate(fixture.pool, 0);
        sbuf_t         *input  = test == 0 ? sbufCreateSplice(64) : sbufCreate(64);
        if (test != 0)
        {
            sbufSetLength(input, 4);
            memoryCopy(input->data, "\r\n\r\n", 4);
            bufferstreamPush(&stream, input);
        }
        const pid_t child = fork();
        require(child >= 0, "failed to fork ordinary-stream representation test");
        if (child == 0)
        {
            if (test == 0)
                bufferstreamPush(&stream, input);
            else
            {
                /* The test corrupts representation after valid admission to
                 * exercise each inspection boundary's own ordinary check. */
                input->flags |= kSbufFlagSplice;
                uint8_t output[4];
                size_t  at = SIZE_MAX;
                if (test == 1)
                    discard bufferstreamViewByteAt(&stream, 0);
                else if (test == 2)
                    bufferstreamCopyBytesAt(&stream, 0, output, sizeof(output));
                else if (test == 3)
                    discard bufferstreamFindCRLF(&stream, &at);
                else
                    discard bufferstreamFindDoubleCRLF(&stream, &at);
            }
            _Exit(kChildReturned);
        }
        int status = 0;
        require(waitpid(child, &status, 0) == child, "failed to wait for representation test");
        require(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT,
                "ordinary stream admission or inspection accepted a splice entry");
        if (test == 0)
            sbufDestroy(input);
        bufferstreamDestroy(&stream);
    }
    poolFixtureDestroy(&fixture);
}
#endif
