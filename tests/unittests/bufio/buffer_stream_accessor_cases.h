/* BufferStream accessor and ordinary-admission cases for bufio_contract_test.c.
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
    require(sbufGetLeftCapacity(read) == 48, "lazy initialization lost the exact-read padding budget");
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
