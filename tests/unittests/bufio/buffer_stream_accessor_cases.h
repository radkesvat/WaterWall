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
    buffer_stream_t stream;
    bufferstreamInitEmpty(&stream, fixture.pool, 0);
    sbuf_t     *input = sbufCreateSplice(64);
    const pid_t child = fork();
    require(child >= 0, "failed to fork ordinary-stream representation test");
    if (child == 0)
    {
        bufferstreamPush(&stream, input);
        _Exit(kChildReturned);
    }
    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for representation test");
    require(WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT, "ordinary stream accepted an empty splice wrapper");
    sbufDestroy(input);
    bufferstreamDestroy(&stream);
    poolFixtureDestroy(&fixture);
}
#endif
