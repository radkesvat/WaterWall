#include "wwapi.h"

#include "buffer_pool_internal.h"

#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

enum
{
    kChildReturned              = 66,
    kCoalescingMaximumInputSize = 4096,
    kTestLargeBufferSize        = 32768,
    kTestSmallBufferSize        = 4096,
    kTestPoolWidth              = 16,
    kTemporaryBufferCapacity    = 64
};

typedef struct pool_fixture_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *pool;
} pool_fixture_t;

typedef struct counting_lifetime_s
{
    sbuf_lifetime_t lifetime;
    uint32_t        retains;
    uint32_t        releases;
} counting_lifetime_t;

typedef enum expected_exact_tier_e
{
    kExpectedExactSmall,
    kExpectedExactLarge,
    kExpectedExactGrown
} expected_exact_tier_e;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static void fillPattern(sbuf_t *buf, uint8_t seed)
{
    uint8_t *bytes = sbufGetMutablePtr(buf);
    for (uint32_t i = 0; i < sbufGetLength(buf); ++i)
    {
        bytes[i] = (uint8_t) (seed + i);
    }
}

static void requireSamePayload(const sbuf_t *actual, const sbuf_t *expected, const char *message)
{
    require(sbufGetLength(actual) == sbufGetLength(expected), message);
    require(memoryEqual(sbufGetRawPtr(actual), sbufGetRawPtr(expected), sbufGetLength(expected)), message);
}

static pool_fixture_t poolFixtureCreate(uint32_t large_size, uint32_t small_size, uint16_t large_padding,
                                        uint16_t small_padding)
{
    pool_fixture_t fixture = {
        .large_master = masterpoolCreateWithCapacity(kTestPoolWidth * 2U),
        .small_master = masterpoolCreateWithCapacity(kTestPoolWidth * 2U),
        .pool         = NULL,
    };

    require(fixture.large_master != NULL && fixture.small_master != NULL, "failed to create BufferStream master pools");
    fixture.pool = bufferpoolCreate(fixture.large_master, fixture.small_master, kTestPoolWidth, large_size, small_size);
    require(fixture.pool != NULL, "failed to create BufferStream test pool");
    bufferpoolUpdateAllocationPaddings(fixture.pool, large_padding, small_padding);
    return fixture;
}

static void poolFixtureDestroy(pool_fixture_t *fixture)
{
    bufferpoolDestroy(fixture->pool);
    masterpoolMakeEmpty(fixture->large_master);
    masterpoolMakeEmpty(fixture->small_master);
    masterpoolDestroy(fixture->large_master);
    masterpoolDestroy(fixture->small_master);
    memoryZero(fixture, sizeof(*fixture));
}

static size_t streamQueueCount(const buffer_stream_t *stream)
{
    return (size_t) bs_doublequeue_t_size(&stream->q);
}

static sbuf_t *makePooledBuffer(buffer_pool_t *pool, bool large, uint32_t length, uint32_t cursor_offset, uint8_t seed)
{
    sbuf_t *buf = large ? bufferpoolGetLargeBuffer(pool) : bufferpoolGetSmallBuffer(pool);
    require(cursor_offset <= sbufGetMaximumWriteableSize(buf), "test cursor offset exceeds pooled buffer capacity");
    if (cursor_offset > 0)
    {
        sbufSetLength(buf, cursor_offset);
        sbufShiftRight(buf, cursor_offset);
    }
    require(length <= sbufGetMaximumWriteableSize(buf), "test payload exceeds cursor-relative buffer capacity");
    sbufSetLength(buf, length);
    fillPattern(buf, seed);
    return buf;
}

static sbuf_t *makeLargePooledBuffer(buffer_pool_t *pool, uint32_t length, uint32_t cursor_offset, uint8_t seed)
{
    sbuf_t *buf = bufferpoolGetLargeBuffer(pool);
    if (cursor_offset > 0)
    {
        require(cursor_offset <= sbufGetMaximumWriteableSize(buf), "large-buffer cursor offset is out of range");
        sbufSetLength(buf, cursor_offset);
        sbufShiftRight(buf, cursor_offset);
    }
    buf = sbufReserveSpace(buf, length);
    require(length <= sbufGetMaximumWriteableSize(buf), "grown large buffer cannot hold the requested test payload");
    sbufSetLength(buf, length);
    fillPattern(buf, seed);
    return buf;
}

static void requirePatternRange(const sbuf_t *buf, uint32_t at, uint32_t length, uint8_t seed, const char *message)
{
    require(at <= sbufGetLength(buf) && length <= sbufGetLength(buf) - at, message);
    const uint8_t *bytes = (const uint8_t *) sbufGetRawPtr(buf) + at;
    for (uint32_t i = 0; i < length; ++i)
    {
        if (bytes[i] != (uint8_t) (seed + i))
        {
            fprintf(stderr, "FAIL: %s (offset=%u)\n", message, at + i);
            exit(1);
        }
    }
}

static void countingLifetimeRetain(sbuf_lifetime_t *lifetime)
{
    counting_lifetime_t *counting = (counting_lifetime_t *) lifetime;
    counting->retains++;
}

static void countingLifetimeRelease(sbuf_lifetime_t *lifetime)
{
    counting_lifetime_t *counting = (counting_lifetime_t *) lifetime;
    counting->releases++;
}

static counting_lifetime_t countingLifetimeCreate(void)
{
    return (counting_lifetime_t) {
        .lifetime = {.retain = countingLifetimeRetain, .release = countingLifetimeRelease},
        .retains  = 0,
        .releases = 0,
    };
}

static void recycleIdealRead(buffer_stream_t *stream)
{
    sbuf_t *buf = bufferstreamIdealRead(stream);
    bufferpoolReuseBuffer(stream->pool, buf);
}

static sbuf_t *makeSourceWithCursorPast(uint32_t cursor)
{
    sbuf_t *source = sbufCreate(128);
    sbufSetLength(source, cursor);
    sbufShiftRight(source, cursor);
    return source;
}

static sbuf_t *makeSentinelDestination(void)
{
    static const uint8_t sentinel[] = {0xA1, 0xB2, 0xC3};

    sbuf_t *dest = sbufCreate(64);
    sbufSetLength(dest, sizeof(sentinel));
    sbufWrite(dest, sentinel, sizeof(sentinel));
    return dest;
}

static void requireSentinelDestinationUnchanged(const sbuf_t *dest, const char *message)
{
    static const uint8_t sentinel[] = {0xA1, 0xB2, 0xC3};

    require(dest->curpos == 0, message);
    require(sbufGetLength(dest) == sizeof(sentinel), message);
    require(memoryEqual(sbufGetRawPtr(dest), sentinel, sizeof(sentinel)), message);
}

static void testDuplicateToCopiesCompleteSource(void)
{
    sbuf_t *source = sbufCreateWithPadding(64, 64);
    sbufSetLength(source, 32);
    sbufShiftLeft(source, 16);
    fillPattern(source, 0x20);

    sbuf_t *dest = sbufCreateWithPadding(64, 64);
    require(sbufDuplicateTo(source, dest), "sbufDuplicateTo rejected a representable source");
    require(dest->curpos == source->curpos, "sbufDuplicateTo did not preserve the source cursor");
    requireSamePayload(dest, source, "sbufDuplicateTo did not copy the complete source payload");

    sbufDestroy(dest);
    sbufDestroy(source);
}

static void testDuplicateToRejectsCursorPastCapacity(void)
{
    sbuf_t *source = makeSourceWithCursorPast(96);
    sbuf_t *dest   = makeSentinelDestination();

    require(! sbufDuplicateTo(source, dest), "sbufDuplicateTo accepted a source cursor past destination capacity");
    requireSentinelDestinationUnchanged(dest, "a rejected cursor geometry modified the destination");

    sbufDestroy(dest);
    sbufDestroy(source);
}

static void testDuplicateToRejectsIncompletePayload(void)
{
    sbuf_t *source = sbufCreateWithPadding(64, 32);
    sbufSetLength(source, 48);
    fillPattern(source, 0x40);

    sbuf_t *dest = makeSentinelDestination();
    require(! sbufDuplicateTo(source, dest), "sbufDuplicateTo accepted a destination that would truncate payload");
    requireSentinelDestinationUnchanged(dest, "a rejected payload geometry modified the destination");

    sbufDestroy(dest);
    sbufDestroy(source);
}

static void testDuplicateToAcceptsEmptyExactEndCursor(void)
{
    sbuf_t *source = makeSourceWithCursorPast(64);
    sbuf_t *dest   = sbufCreate(64);

    require(sbufDuplicateTo(source, dest), "sbufDuplicateTo rejected an empty exact-end cursor");
    require(dest->curpos == sbufGetTotalCapacity(dest), "the empty exact-end cursor was not preserved");
    require(sbufGetLength(dest) == 0, "the empty exact-end duplicate gained payload");

    sbufDestroy(dest);
    sbufDestroy(source);
}

static void testDuplicatePreservesCompleteSource(void)
{
    sbuf_t *source = sbufCreateWithPadding(64, 64);
    sbufSetLength(source, 64);
    sbufShiftLeft(source, 32);
    fillPattern(source, 0x60);

    sbuf_t *duplicate = sbufDuplicate(source);
    require(duplicate->curpos == source->curpos, "sbufDuplicate did not preserve the source cursor");
    require(sbufGetLeftPadding(duplicate) == sbufGetLeftPadding(source),
            "sbufDuplicate did not preserve the padding geometry");
    requireSamePayload(duplicate, source, "sbufDuplicate did not preserve the complete source payload");

    sbufDestroy(duplicate);
    sbufDestroy(source);
}

static void testPooledDuplicateHandlesConsumedPadding(buffer_pool_t *pool)
{
    sbuf_t *source = bufferpoolGetSmallBuffer(pool);
    sbufSetLength(source, bufferpoolGetSmallBufferSize(pool));
    sbufShiftLeft(source, 32);
    fillPattern(source, 0x80);

    require(sbufGetLength(source) > bufferpoolGetSmallBufferSize(pool),
            "the pooled duplicate regression did not consume left padding");

    sbuf_t *duplicate = sbufDuplicateByPool(pool, source);
    requireSamePayload(duplicate, source, "sbufDuplicateByPool truncated a source that consumed left padding");

    bufferpoolReuseBuffer(pool, duplicate);
    bufferpoolReuseBuffer(pool, source);
}

static void testViewByteAcrossQueuedBuffers(buffer_pool_t *pool)
{
    static const uint8_t first_bytes[]  = {0x00, 0xFF, 0x11};
    static const uint8_t second_bytes[] = {0x22, 0x33};

    buffer_stream_t stream = bufferstreamCreate(pool, 0);
    sbuf_t         *first  = bufferpoolGetSmallBuffer(pool);
    sbuf_t         *second = bufferpoolGetSmallBuffer(pool);

    sbufSetLength(first, sizeof(first_bytes));
    sbufWrite(first, first_bytes, sizeof(first_bytes));
    sbufSetLength(second, sizeof(second_bytes));
    sbufWrite(second, second_bytes, sizeof(second_bytes));
    bufferstreamPush(&stream, first);
    bufferstreamPush(&stream, second);

    require(bufferstreamViewByteAt(&stream, 0) == 0x00, "byte view changed a zero byte");
    require(bufferstreamViewByteAt(&stream, 1) == 0xFF, "byte view cannot represent a 0xFF data byte");
    require(bufferstreamViewByteAt(&stream, 2) == 0x11, "byte view returned the wrong first-buffer tail");
    require(bufferstreamViewByteAt(&stream, 3) == 0x22, "byte view failed at a queued-buffer boundary");
    require(bufferstreamViewByteAt(&stream, 4) == 0x33, "byte view returned the wrong final byte");

    bufferstreamDestroy(&stream);
}

static void testOrdinaryPushCompatibility(void)
{
    pool_fixture_t  fixture = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 64);
    buffer_stream_t stream  = bufferstreamCreate(fixture.pool, 0);
    sbuf_t         *first   = makePooledBuffer(fixture.pool, false, 3, 0, 0x10);
    sbuf_t         *second  = makePooledBuffer(fixture.pool, false, 2, 0, 0x20);

    bufferstreamPush(&stream, first);
    bufferstreamPush(&stream, second);
    require(streamQueueCount(&stream) == 2, "ordinary push coalesced two fitting chunks");
    require(bufferstreamGetBufLen(&stream) == 5, "ordinary push changed logical stream size");

    sbuf_t *read = bufferstreamIdealRead(&stream);
    require(read == first, "ordinary push changed first-chunk identity");
    requirePatternRange(read, 0, 3, 0x10, "ordinary push changed first-chunk data");
    bufferpoolReuseBuffer(fixture.pool, read);
    read = bufferstreamIdealRead(&stream);
    require(read == second, "ordinary push changed second-chunk identity");
    requirePatternRange(read, 0, 2, 0x20, "ordinary push changed second-chunk data");
    bufferpoolReuseBuffer(fixture.pool, read);
    bufferstreamDestroy(&stream);

    stream           = bufferstreamCreate(fixture.pool, 0);
    sbuf_t *empty    = makePooledBuffer(fixture.pool, false, 0, 0, 0);
    sbuf_t *nonempty = makePooledBuffer(fixture.pool, false, 2, 0, 0x30);
    bufferstreamPush(&stream, empty);
    bufferstreamPush(&stream, nonempty);
    require(streamQueueCount(&stream) == 2, "ordinary push dropped a zero-length chunk");
    require(bufferstreamGetBufLen(&stream) == 2, "zero-length push changed logical size");
    read = bufferstreamIdealRead(&stream);
    require(read == empty && sbufGetLength(read) == 0, "ordinary push changed queued zero-length behavior");
    require(bufferstreamGetBufLen(&stream) == 2, "reading a zero-length chunk consumed logical bytes");
    bufferpoolReuseBuffer(fixture.pool, read);
    read = bufferstreamIdealRead(&stream);
    require(read == nonempty, "zero-length chunk changed following chunk identity");
    bufferpoolReuseBuffer(fixture.pool, read);
    bufferstreamDestroy(&stream);

    stream = bufferstreamCreate(fixture.pool, 0);
    empty  = makePooledBuffer(fixture.pool, false, 0, 0, 0);
    bufferstreamPush(&stream, empty);
    require(bufferstreamIsEmpty(&stream), "zero-only ordinary stream is not logically empty");
    require(streamQueueCount(&stream) == 1, "zero-only ordinary push did not preserve its chunk");
    bufferstreamDestroy(&stream);
    poolFixtureDestroy(&fixture);
}

static void testCoalescingOneByteFragmentsAndDequeBack(void)
{
    pool_fixture_t fixture    = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 64);
    uint32_t       small_size = bufferpoolGetSmallBufferSize(fixture.pool);
    const uint32_t total      = small_size * 2U + 3U;
    uint8_t       *expected   = memoryAllocate(total);
    require(expected != NULL, "failed to allocate one-byte coalescing expectation");

    buffer_stream_t stream = bufferstreamCreate(fixture.pool, 0);
    for (uint32_t i = 0; i < total; ++i)
    {
        expected[i] = (uint8_t) i;
        bufferstreamPushCoalescing(&stream, makePooledBuffer(fixture.pool, false, 1, 0, (uint8_t) i));
    }
    require(bufferstreamGetBufLen(&stream) == total, "one-byte coalescing changed stream size");
    require(streamQueueCount(&stream) == (total + small_size - 1U) / small_size,
            "one-byte coalescing retained more than the capacity-derived queue minimum");

    sbuf_t *all = bufferstreamFullRead(&stream);
    require(sbufGetLength(all) == total, "full read changed one-byte coalesced length");
    require(memoryEqual(sbufGetRawPtr(all), expected, total), "one-byte coalescing changed FIFO byte order");
    bufferpoolReuseBuffer(fixture.pool, all);
    bufferstreamDestroy(&stream);
    memoryFree(expected);

    stream         = bufferstreamCreate(fixture.pool, 0);
    sbuf_t *full   = makePooledBuffer(fixture.pool, false, small_size, 0, 0x10);
    sbuf_t *second = makePooledBuffer(fixture.pool, false, 1, 0, 0xA0);
    bufferstreamPushCoalescing(&stream, full);
    bufferstreamPushCoalescing(&stream, second);
    require(streamQueueCount(&stream) == 2, "full tail did not force a second queue entry");
    bufferstreamPushCoalescing(&stream, makePooledBuffer(fixture.pool, false, 2, 0, 0xB0));
    require(streamQueueCount(&stream) == 2, "coalescing did not use the actual deque back");
    require(*bs_doublequeue_t_back(&stream.q) == second, "coalescing removed or replaced the deque back");
    require(sbufGetLength(second) == 3, "coalescing did not extend the second tail");
    requirePatternRange(second, 0, 1, 0xA0, "coalescing overwrote the second tail prefix");
    requirePatternRange(second, 1, 2, 0xB0, "coalescing appended at the wrong tail offset");
    recycleIdealRead(&stream);
    recycleIdealRead(&stream);
    bufferstreamDestroy(&stream);

    stream              = bufferstreamCreate(fixture.pool, 0);
    sbuf_t *older_spare = makePooledBuffer(fixture.pool, false, 1, 0, 0x31);
    full                = makePooledBuffer(fixture.pool, false, small_size, 0, 0x41);
    sbuf_t *new_source  = makePooledBuffer(fixture.pool, false, 2, 0, 0x51);
    bufferstreamPushCoalescing(&stream, older_spare);
    bufferstreamPushCoalescing(&stream, full);
    bufferstreamPushCoalescing(&stream, new_source);
    require(streamQueueCount(&stream) == 3, "coalescing searched an older queue entry for spare capacity");
    require(*bs_doublequeue_t_front(&stream.q) == older_spare && *bs_doublequeue_t_back(&stream.q) == new_source,
            "older-entry exclusion changed ordinary queue order or identity");
    require(sbufGetLength(older_spare) == 1 && sbufGetLength(full) == small_size && sbufGetLength(new_source) == 2,
            "older-entry exclusion changed a queued buffer length");
    recycleIdealRead(&stream);
    recycleIdealRead(&stream);
    recycleIdealRead(&stream);
    require(bufferstreamIsEmpty(&stream) && streamQueueCount(&stream) == 0,
            "older-entry exclusion did not drain cleanly");
    bufferstreamDestroy(&stream);
    poolFixtureDestroy(&fixture);
}

static void testCoalescingCopyAndInputBoundaries(void)
{
    static const uint32_t sizes[]          = {255, 256, 257, 512, 1024, 4096};
    static const uint32_t dest_offsets[]   = {1, 15, 31, 32, 63, 1};
    static const uint32_t source_offsets[] = {63, 32, 31, 15, 1, 63};

    pool_fixture_t fixture = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 64);
    for (size_t i = 0; i < ARRAY_SIZE(sizes); ++i)
    {
        buffer_stream_t stream = bufferstreamCreate(fixture.pool, 0);
        sbuf_t         *tail   = makePooledBuffer(fixture.pool, true, 7, dest_offsets[i], (uint8_t) (0x10U + i));
        sbuf_t *source = makePooledBuffer(fixture.pool, true, sizes[i], source_offsets[i], (uint8_t) (0x80U + i));
        const uint32_t saved_curpos = tail->curpos;
        const uint32_t saved_left   = sbufGetLeftCapacity(tail);
        const uint16_t saved_lpad   = sbufGetLeftPadding(tail);

        bufferstreamPushCoalescing(&stream, tail);
        bufferstreamPushCoalescing(&stream, source);
        require(streamQueueCount(&stream) == 1, "eligible copy-boundary input did not coalesce");
        require(bufferstreamGetBufLen(&stream) == 7U + sizes[i], "copy-boundary coalescing changed stream size");

        sbuf_t *combined = bufferstreamIdealRead(&stream);
        require(combined == tail, "copy-boundary coalescing replaced the tail allocation");
        require(tail->curpos == saved_curpos && sbufGetLeftCapacity(tail) == saved_left &&
                    sbufGetLeftPadding(tail) == saved_lpad,
                "copy-boundary coalescing changed tail cursor or padding geometry");
        requirePatternRange(combined, 0, 7, (uint8_t) (0x10U + i), "copy-boundary coalescing changed tail bytes");
        requirePatternRange(
            combined, 7, sizes[i], (uint8_t) (0x80U + i), "copy-boundary coalescing changed appended bytes");
        bufferpoolReuseBuffer(fixture.pool, combined);
        bufferstreamDestroy(&stream);
    }

    buffer_stream_t stream = bufferstreamCreate(fixture.pool, 0);
    sbuf_t         *tail   = makePooledBuffer(fixture.pool, true, 7, 1, 0x11);
    sbuf_t         *over   = makePooledBuffer(fixture.pool, true, kCoalescingMaximumInputSize + 1U, 15, 0x72);
    bufferstreamPushCoalescing(&stream, tail);
    bufferstreamPushCoalescing(&stream, over);
    require(streamQueueCount(&stream) == 2, "4097-byte input crossed the 4096-byte coalescing cap");
    require(bufferstreamGetBufLen(&stream) == 7U + kCoalescingMaximumInputSize + 1U,
            "over-cap fallback changed aggregate stream size");
    require(*bs_doublequeue_t_back(&stream.q) == over, "over-cap input lost ordinary enqueue identity");
    require(sbufGetLength(tail) == 7 && sbufGetLength(over) == kCoalescingMaximumInputSize + 1U,
            "over-cap fallback changed an input length");
    recycleIdealRead(&stream);
    recycleIdealRead(&stream);
    require(bufferstreamIsEmpty(&stream) && streamQueueCount(&stream) == 0, "over-cap fallback did not drain cleanly");
    bufferstreamDestroy(&stream);
    poolFixtureDestroy(&fixture);
}

static void testCoalescingConsumedTailAndFitPolicy(void)
{
    pool_fixture_t  fixture      = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 64);
    buffer_stream_t stream       = bufferstreamCreate(fixture.pool, 0);
    sbuf_t         *tail         = makePooledBuffer(fixture.pool, true, 11, 31, 0x20);
    sbuf_t         *source       = makePooledBuffer(fixture.pool, true, 257, 15, 0x90);
    const uint32_t  saved_curpos = tail->curpos;
    const uint32_t  saved_left   = sbufGetLeftCapacity(tail);
    const uint16_t  saved_lpad   = sbufGetLeftPadding(tail);
    bufferstreamPushCoalescing(&stream, tail);
    bufferstreamPushCoalescing(&stream, source);
    require(streamQueueCount(&stream) == 1, "partially consumed tail was not coalesced");
    sbuf_t *combined = bufferstreamIdealRead(&stream);
    require(combined == tail && tail->curpos == saved_curpos && sbufGetLeftCapacity(tail) == saved_left &&
                sbufGetLeftPadding(tail) == saved_lpad,
            "partially consumed tail geometry changed during append");
    requirePatternRange(combined, 0, 11, 0x20, "partially consumed tail bytes were overwritten");
    requirePatternRange(combined, 11, 257, 0x90, "append did not begin at the consumed tail's logical end");
    bufferpoolReuseBuffer(fixture.pool, combined);
    bufferstreamDestroy(&stream);

    const uint32_t incoming = 257;
    stream                  = bufferstreamCreate(fixture.pool, 0);
    tail                    = makePooledBuffer(fixture.pool, true, 0, 31, 0);
    const uint32_t maximum  = sbufGetMaximumWriteableSize(tail);
    sbufSetLength(tail, maximum - incoming);
    fillPattern(tail, 0x33);
    source = makePooledBuffer(fixture.pool, true, incoming, 15, 0xB0);
    bufferstreamPushCoalescing(&stream, tail);
    bufferstreamPushCoalescing(&stream, source);
    require(streamQueueCount(&stream) == 1, "exact tail fit did not coalesce");
    combined = bufferstreamIdealRead(&stream);
    require(sbufGetLength(combined) == maximum, "exact tail fit did not fill writable capacity");
    requirePatternRange(combined, maximum - incoming, incoming, 0xB0, "exact-fit append bytes are incorrect");
    bufferpoolReuseBuffer(fixture.pool, combined);
    bufferstreamDestroy(&stream);

    stream                  = bufferstreamCreate(fixture.pool, 0);
    tail                    = makePooledBuffer(fixture.pool, true, 0, 31, 0);
    const uint32_t tail_len = sbufGetMaximumWriteableSize(tail) - incoming + 1U;
    sbufSetLength(tail, tail_len);
    fillPattern(tail, 0x44);
    source                         = makePooledBuffer(fixture.pool, true, incoming, 15, 0xC0);
    const uint32_t tail_capacity   = sbufGetTotalCapacity(tail);
    const uint32_t source_capacity = sbufGetTotalCapacity(source);
    uint8_t       *tail_copy       = memoryAllocate(tail_len);
    uint8_t       *source_copy     = memoryAllocate(incoming);
    require(tail_copy != NULL && source_copy != NULL, "failed to allocate no-fit snapshots");
    memoryCopy(tail_copy, sbufGetRawPtr(tail), tail_len);
    memoryCopy(source_copy, sbufGetRawPtr(source), incoming);
    bufferstreamPushCoalescing(&stream, tail);
    bufferstreamPushCoalescing(&stream, source);
    require(streamQueueCount(&stream) == 2, "one-byte-too-large source was partially coalesced");
    require(bufferstreamGetBufLen(&stream) == (size_t) tail_len + incoming,
            "no-fit fallback changed aggregate stream size");
    require(*bs_doublequeue_t_front(&stream.q) == tail && *bs_doublequeue_t_back(&stream.q) == source,
            "no-fit fallback changed ordinary queue identity or order");
    require(sbufGetLength(tail) == tail_len && sbufGetLength(source) == incoming,
            "no-fit fallback changed a buffer length");
    require(sbufGetTotalCapacity(tail) == tail_capacity && sbufGetTotalCapacity(source) == source_capacity,
            "no-fit fallback grew or replaced an input allocation");
    require(memoryEqual(sbufGetRawPtr(tail), tail_copy, tail_len) &&
                memoryEqual(sbufGetRawPtr(source), source_copy, incoming),
            "no-fit fallback copied a partial source or changed existing bytes");
    memoryFree(tail_copy);
    memoryFree(source_copy);
    recycleIdealRead(&stream);
    recycleIdealRead(&stream);
    require(bufferstreamIsEmpty(&stream) && streamQueueCount(&stream) == 0, "no-fit fallback did not drain cleanly");
    bufferstreamDestroy(&stream);
    poolFixtureDestroy(&fixture);
}

static uint32_t populateCoalescedReadStream(buffer_pool_t *pool, buffer_stream_t *stream)
{
    static const uint32_t fragments[] = {10, 200, 60, 40, 250, 5};
    uint32_t              offset      = 0;
    for (size_t i = 0; i < ARRAY_SIZE(fragments); ++i)
    {
        bufferstreamPushCoalescing(stream, makePooledBuffer(pool, false, fragments[i], 0, (uint8_t) offset));
        offset += fragments[i];
    }
    require(streamQueueCount(stream) == 3, "read-API fixture did not create the intended coalesced queue geometry");
    return offset;
}

static void testCoalescingReadApisAndViews(void)
{
    pool_fixture_t fixture = poolFixtureCreate(1024, 256, 64, 64);

    buffer_stream_t stream = bufferstreamCreate(fixture.pool, 0);
    const uint32_t  total  = populateCoalescedReadStream(fixture.pool, &stream);
    require(bufferstreamGetBufLen(&stream) == total, "coalesced read fixture has the wrong logical size");
    for (uint32_t i = 0; i < total; ++i)
    {
        require(bufferstreamViewByteAt(&stream, i) == (uint8_t) i, "byte view changed the coalesced logical stream");
    }
    uint8_t view[70];
    bufferstreamViewBytesAt(&stream, 205, view, sizeof(view));
    for (uint32_t i = 0; i < sizeof(view); ++i)
    {
        require(view[i] == (uint8_t) (205U + i), "range view changed bytes across a coalesced queue boundary");
    }

    sbuf_t *read = bufferstreamReadExact(&stream, 230);
    require(sbufGetLength(read) == 230, "ReadExact returned the wrong coalesced length");
    requirePatternRange(read, 0, 230, 0, "ReadExact changed coalesced byte order");
    bufferpoolReuseBuffer(fixture.pool, read);
    require(bufferstreamGetBufLen(&stream) == total - 230U, "ReadExact changed remaining logical size");
    read = bufferstreamFullRead(&stream);
    require(sbufGetLength(read) == total - 230U, "FullRead returned the wrong post-ReadExact length");
    requirePatternRange(read, 0, total - 230U, (uint8_t) 230, "FullRead changed post-ReadExact byte order");
    bufferpoolReuseBuffer(fixture.pool, read);
    bufferstreamDestroy(&stream);

    stream = bufferstreamCreate(fixture.pool, 0);
    discard populateCoalescedReadStream(fixture.pool, &stream);
    read = bufferstreamReadAtLeast(&stream, 220);
    require(sbufGetLength(read) == 310, "ReadAtLeast did not preserve complete queued chunks");
    requirePatternRange(read, 0, 310, 0, "ReadAtLeast changed coalesced byte order");
    bufferpoolReuseBuffer(fixture.pool, read);
    read = bufferstreamFullRead(&stream);
    require(sbufGetLength(read) == total - 310U, "FullRead returned the wrong post-ReadAtLeast length");
    requirePatternRange(read, 0, total - 310U, (uint8_t) 310, "post-ReadAtLeast bytes are out of order");
    bufferpoolReuseBuffer(fixture.pool, read);
    bufferstreamDestroy(&stream);

    stream = bufferstreamCreate(fixture.pool, 0);
    discard populateCoalescedReadStream(fixture.pool, &stream);
    read = bufferstreamFullRead(&stream);
    require(sbufGetLength(read) == total, "FullRead changed the complete coalesced length");
    requirePatternRange(read, 0, total, 0, "FullRead changed the complete coalesced byte stream");
    bufferpoolReuseBuffer(fixture.pool, read);
    bufferstreamDestroy(&stream);
    poolFixtureDestroy(&fixture);
}

static void testCoalescingImmediatePoolSettlement(void)
{
    pool_fixture_t fixture = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 64);
    sbuf_t        *warm    = bufferpoolGetSmallBuffer(fixture.pool);
    bufferpoolReuseBuffer(fixture.pool, warm);

    uint32_t large_baseline = 0;
    uint32_t small_baseline = 0;
    bufferpoolCachedTierCountsForTest(fixture.pool, &large_baseline, &small_baseline);
    require(small_baseline >= 2, "small-tier cache did not warm for settlement test");

    buffer_stream_t stream      = bufferstreamCreate(fixture.pool, 0);
    sbuf_t         *tail        = makePooledBuffer(fixture.pool, false, 4, 0, 0x10);
    sbuf_t         *source      = makePooledBuffer(fixture.pool, false, 3, 0, 0x20);
    uint32_t        large_count = 0;
    uint32_t        small_count = 0;
    bufferpoolCachedTierCountsForTest(fixture.pool, &large_count, &small_count);
    require(small_count + 2U == small_baseline, "settlement fixture did not check out exactly two small buffers");

    bufferstreamPushCoalescing(&stream, tail);
    bufferstreamPushCoalescing(&stream, source);
    bufferpoolCachedTierCountsForTest(fixture.pool, &large_count, &small_count);
    require(streamQueueCount(&stream) == 1, "eligible settlement source did not coalesce");
    require(small_count + 1U == small_baseline, "eligible source was not returned immediately and exactly once");

    sbuf_t *read = bufferstreamIdealRead(&stream);
    require(read == tail, "settlement test lost the retained tail");
    bufferpoolCachedTierCountsForTest(fixture.pool, &large_count, &small_count);
    require(small_count + 1U == small_baseline, "reading the tail recycled it before ownership was returned");
    bufferpoolReuseBuffer(fixture.pool, read);
    bufferpoolCachedTierCountsForTest(fixture.pool, &large_count, &small_count);
    require(small_count == small_baseline, "retained tail did not settle exactly once");
    bufferstreamDestroy(&stream);
    poolFixtureDestroy(&fixture);
}

static void testCoalescingLifetimeExclusions(void)
{
    pool_fixture_t fixture = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 64);

    counting_lifetime_t source_lifetime = countingLifetimeCreate();
    buffer_stream_t     stream          = bufferstreamCreate(fixture.pool, 0);
    sbuf_t             *tail            = makePooledBuffer(fixture.pool, false, 4, 0, 0x10);
    sbuf_t             *source          = makePooledBuffer(fixture.pool, false, 3, 0, 0x20);
    sbufAttachLifetime(source, &source_lifetime.lifetime);
    bufferstreamPushCoalescing(&stream, tail);
    bufferstreamPushCoalescing(&stream, source);
    require(streamQueueCount(&stream) == 2, "lifetime-bearing source was coalesced");
    require(bufferstreamGetBufLen(&stream) == 7 && *bs_doublequeue_t_front(&stream.q) == tail &&
                *bs_doublequeue_t_back(&stream.q) == source,
            "lifetime-bearing source changed ordinary queue size, order, or identity");
    require(sbufGetLifetime(tail) == NULL && sbufGetLifetime(source) == &source_lifetime.lifetime,
            "source lifetime metadata moved to a different buffer");
    require(sbufGetLength(tail) == 4 && sbufGetLength(source) == 3,
            "source lifetime exclusion changed a buffer length");
    requirePatternRange(tail, 0, 4, 0x10, "source lifetime exclusion changed tail data");
    requirePatternRange(source, 0, 3, 0x20, "source lifetime exclusion changed source data");
    require(source_lifetime.retains == 0 && source_lifetime.releases == 0,
            "source lifetime settled before ordinary stream cleanup");
    sbuf_t *read = bufferstreamIdealRead(&stream);
    require(read == tail && source_lifetime.releases == 0, "source lifetime settled before its original queue entry");
    bufferpoolReuseBuffer(fixture.pool, read);
    read = bufferstreamIdealRead(&stream);
    require(read == source && sbufGetLifetime(read) == &source_lifetime.lifetime && source_lifetime.releases == 0,
            "source lifetime association changed before ordinary read settlement");
    bufferpoolReuseBuffer(fixture.pool, read);
    require(source_lifetime.retains == 0 && source_lifetime.releases == 1,
            "source lifetime did not settle exactly once at its ordinary read point");
    require(bufferstreamIsEmpty(&stream) && streamQueueCount(&stream) == 0,
            "source lifetime exclusion did not drain cleanly");
    bufferstreamDestroy(&stream);

    counting_lifetime_t tail_lifetime = countingLifetimeCreate();
    stream                            = bufferstreamCreate(fixture.pool, 0);
    tail                              = makePooledBuffer(fixture.pool, false, 4, 0, 0x30);
    source                            = makePooledBuffer(fixture.pool, false, 3, 0, 0x40);
    sbufAttachLifetime(tail, &tail_lifetime.lifetime);
    bufferstreamPushCoalescing(&stream, tail);
    bufferstreamPushCoalescing(&stream, source);
    require(streamQueueCount(&stream) == 2, "lifetime-bearing tail accepted unrelated source bytes");
    require(bufferstreamGetBufLen(&stream) == 7 && *bs_doublequeue_t_front(&stream.q) == tail &&
                *bs_doublequeue_t_back(&stream.q) == source,
            "lifetime-bearing tail changed ordinary queue size, order, or identity");
    require(sbufGetLifetime(tail) == &tail_lifetime.lifetime && sbufGetLifetime(source) == NULL,
            "tail lifetime metadata moved to a different buffer");
    require(sbufGetLength(tail) == 4 && sbufGetLength(source) == 3, "tail lifetime exclusion changed a buffer length");
    requirePatternRange(tail, 0, 4, 0x30, "tail lifetime exclusion changed tail data");
    requirePatternRange(source, 0, 3, 0x40, "tail lifetime exclusion changed source data");
    require(tail_lifetime.retains == 0 && tail_lifetime.releases == 0,
            "tail lifetime settled before ordinary stream destruction");
    read = bufferstreamIdealRead(&stream);
    require(read == tail && sbufGetLifetime(read) == &tail_lifetime.lifetime && tail_lifetime.releases == 0,
            "tail lifetime association changed before ordinary read settlement");
    bufferpoolReuseBuffer(fixture.pool, read);
    require(tail_lifetime.releases == 1, "tail lifetime did not settle at its ordinary read point");
    read = bufferstreamIdealRead(&stream);
    require(read == source && sbufGetLifetime(read) == NULL,
            "tail lifetime exclusion changed the following source metadata");
    bufferpoolReuseBuffer(fixture.pool, read);
    bufferstreamDestroy(&stream);
    require(tail_lifetime.retains == 0 && tail_lifetime.releases == 1, "tail lifetime did not settle exactly once");
    poolFixtureDestroy(&fixture);
}

static sbuf_t *createTemporaryBuffer(uint32_t length, uint8_t seed)
{
    require(length <= kTemporaryBufferCapacity, "temporary test payload exceeds its allocation");
    sbuf_t *buffer = memoryAllocateAligned(sizeof(sbuf_t) + kTemporaryBufferCapacity, kSbufAllocationAlignment);
    require(buffer != NULL, "failed to allocate temporary test buffer storage");
    *buffer = (sbuf_t) {
        .curpos       = 0,
        .len          = length,
        .capacity     = kTemporaryBufferCapacity,
        .l_pad        = 0,
        .is_temporary = true,
        .lifetime     = NULL,
    };
    fillPattern(buffer, seed);
    return buffer;
}

static void testCoalescingTemporaryAndZeroExclusions(void)
{
    pool_fixture_t fixture = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 64);

    buffer_stream_t stream = bufferstreamCreate(fixture.pool, 0);
    sbuf_t         *tail   = makePooledBuffer(fixture.pool, false, 4, 0, 0x10);
    sbuf_t         *source = createTemporaryBuffer(3, 0x20);
    bufferstreamPushCoalescing(&stream, tail);
    bufferstreamPushCoalescing(&stream, source);
    require(streamQueueCount(&stream) == 2, "temporary source was coalesced or recycled immediately");
    require(bufferstreamGetBufLen(&stream) == 7 && *bs_doublequeue_t_front(&stream.q) == tail &&
                *bs_doublequeue_t_back(&stream.q) == source,
            "temporary source changed ordinary queue size, order, or identity");
    require(! tail->is_temporary && source->is_temporary && sbufGetLength(tail) == 4 && sbufGetLength(source) == 3,
            "temporary source exclusion changed flags or lengths");
    requirePatternRange(tail, 0, 4, 0x10, "temporary source exclusion changed tail data");
    requirePatternRange(source, 0, 3, 0x20, "temporary source exclusion changed source data");
    sbuf_t *read = bufferstreamIdealRead(&stream);
    require(read == tail, "temporary source exclusion changed FIFO order");
    bufferpoolReuseBuffer(fixture.pool, read);
    read = bufferstreamIdealRead(&stream);
    require(read == source && read->is_temporary, "temporary source identity or ownership flag changed before read");
    require(bufferstreamIsEmpty(&stream) && streamQueueCount(&stream) == 0,
            "temporary source exclusion did not drain cleanly");
    memoryFreeAligned(source);
    bufferstreamDestroy(&stream);

    stream = bufferstreamCreate(fixture.pool, 0);
    tail   = createTemporaryBuffer(4, 0x30);
    source = makePooledBuffer(fixture.pool, false, 3, 0, 0x40);
    bufferstreamPushCoalescing(&stream, tail);
    bufferstreamPushCoalescing(&stream, source);
    require(streamQueueCount(&stream) == 2, "temporary tail accepted coalesced source bytes");
    require(bufferstreamGetBufLen(&stream) == 7 && *bs_doublequeue_t_front(&stream.q) == tail &&
                *bs_doublequeue_t_back(&stream.q) == source,
            "temporary tail changed ordinary queue size, order, or identity");
    require(tail->is_temporary && ! source->is_temporary && sbufGetLength(tail) == 4 && sbufGetLength(source) == 3,
            "temporary tail exclusion changed flags or lengths");
    requirePatternRange(tail, 0, 4, 0x30, "temporary tail exclusion changed tail data");
    requirePatternRange(source, 0, 3, 0x40, "temporary tail exclusion changed source data");
    read = bufferstreamIdealRead(&stream);
    require(read == tail && read->is_temporary, "temporary tail identity or ownership flag changed before read");
    read = bufferstreamIdealRead(&stream);
    require(read == source, "temporary tail exclusion changed following source FIFO order");
    bufferpoolReuseBuffer(fixture.pool, read);
    require(bufferstreamIsEmpty(&stream) && streamQueueCount(&stream) == 0,
            "temporary tail exclusion did not drain cleanly");
    memoryFreeAligned(tail);
    bufferstreamDestroy(&stream);

    stream        = bufferstreamCreate(fixture.pool, 0);
    tail          = makePooledBuffer(fixture.pool, false, 4, 0, 0x50);
    sbuf_t *empty = makePooledBuffer(fixture.pool, false, 0, 0, 0);
    bufferstreamPushCoalescing(&stream, tail);
    bufferstreamPushCoalescing(&stream, empty);
    require(streamQueueCount(&stream) == 2, "zero-length coalescing input was merged or dropped");
    require(*bs_doublequeue_t_back(&stream.q) == empty, "zero-length coalescing input lost enqueue identity");
    recycleIdealRead(&stream);
    require(bufferstreamIsEmpty(&stream) && streamQueueCount(&stream) == 1,
            "zero-length queue entry changed logical empty state");
    bufferstreamEmpty(&stream);
    bufferstreamDestroy(&stream);
    poolFixtureDestroy(&fixture);
}

static void runExactAllocationCase(pool_fixture_t *fixture, uint16_t use_left_padding, uint32_t bytes,
                                   expected_exact_tier_e expected_tier, bool strip_prefix)
{
    buffer_pool_t *pool       = fixture->pool;
    const uint32_t small_size = bufferpoolGetSmallBufferSize(pool);
    const uint32_t large_size = bufferpoolGetLargeBufferSize(pool);
    const uint16_t small_pad  = bufferpoolGetSmallBufferPadding(pool);
    const uint16_t large_pad  = bufferpoolGetLargeBufferPadding(pool);

    counting_lifetime_t source_lifetime = countingLifetimeCreate();
    buffer_stream_t     stream          = bufferstreamCreate(pool, use_left_padding);
    sbuf_t             *source          = makeLargePooledBuffer(pool, bytes + 1U, 0, 0x21);
    const uint16_t      source_lpad     = sbufGetLeftPadding(source);
    sbufAttachLifetime(source, &source_lifetime.lifetime);
    bufferstreamPush(&stream, source);

    sbuf_t *result = bufferstreamReadExact(&stream, bytes);
    require(sbufGetLength(result) == bytes, "exact-read allocation returned the wrong requested length");
    requirePatternRange(result, 0, bytes, 0x21, "exact-read allocation changed requested bytes");
    require(bufferstreamGetBufLen(&stream) == 1 && streamQueueCount(&stream) == 1,
            "exact-read allocation did not preserve the one-byte source remainder");
    require(*bs_doublequeue_t_front(&stream.q) == source && sbufGetLength(source) == 1,
            "exact-read allocation replaced or resized the source remainder");
    require(sbufGetLeftPadding(source) == source_lpad, "exact-read allocation changed source l_pad");
    require(bufferstreamViewByteAt(&stream, 0) == (uint8_t) (0x21U + bytes),
            "exact-read allocation changed the queued remainder byte");
    require(source_lifetime.retains == 0 && source_lifetime.releases == 0,
            "exact-read allocation settled the source lifetime too early");

    switch (expected_tier)
    {
    case kExpectedExactSmall:
        require(sbufGetTotalCapacityNoPadding(result) == small_size,
                "padding-aware exact read did not select the small tier");
        require(sbufGetLeftPadding(result) == small_pad, "small exact-read result changed physical l_pad");
        require(result->curpos == (uint32_t) small_pad - use_left_padding,
                "small exact-read result consumed the wrong padding budget");
        break;
    case kExpectedExactLarge:
        require(sbufGetTotalCapacityNoPadding(result) == large_size,
                "exact read did not retain the required large tier");
        require(sbufGetLeftPadding(result) == large_pad, "large exact-read result changed physical l_pad");
        require(result->curpos == (uint32_t) large_pad - use_left_padding,
                "large exact-read result consumed the wrong padding budget");
        break;
    case kExpectedExactGrown:
        require(sbufGetTotalCapacityNoPadding(result) > large_size,
                "oversized exact read did not use the reserve-space fallback");
        require(sbufGetLeftPadding(result) == large_pad, "oversized exact read lost full large-tier l_pad");
        require(result->curpos == large_pad, "oversized exact-read fallback did not restore full left capacity");
        break;
    }

    if (strip_prefix)
    {
        require(expected_tier == kExpectedExactSmall && bytes >= use_left_padding,
                "invalid parser-strip exact-read fixture");
        sbufShiftRight(result, use_left_padding);
        require(result->curpos == small_pad && sbufGetLeftCapacity(result) == small_pad,
                "stripping the declared prefix did not restore small-buffer cursor geometry");
        require(sbufGetLength(result) == bytes - use_left_padding,
                "stripping the declared prefix changed payload length incorrectly");
        requirePatternRange(result,
                            0,
                            bytes - use_left_padding,
                            (uint8_t) (0x21U + use_left_padding),
                            "stripping the declared prefix changed payload bytes");
    }

    bufferpoolReuseBuffer(pool, result);
    require(source_lifetime.releases == 0, "recycling exact-read result settled the queued source lifetime");
    bufferstreamEmpty(&stream);
    require(source_lifetime.retains == 0 && source_lifetime.releases == 1,
            "exact-read source remainder did not settle exactly once");
    bufferstreamDestroy(&stream);
}

static void testPaddingAwareExactReadAllocation(void)
{
    const uint16_t u          = 21;
    pool_fixture_t fixture    = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, u, u);
    uint32_t       small_size = bufferpoolGetSmallBufferSize(fixture.pool);
    for (uint32_t bytes = small_size + 1U; bytes <= small_size + u; ++bytes)
    {
        runExactAllocationCase(&fixture, u, bytes, kExpectedExactSmall, bytes == small_size + u);
    }
    runExactAllocationCase(&fixture, u, small_size + u + 1U, kExpectedExactLarge, false);
    runExactAllocationCase(&fixture, u, u - 1U, kExpectedExactSmall, false);
    poolFixtureDestroy(&fixture);

    fixture    = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 64);
    small_size = bufferpoolGetSmallBufferSize(fixture.pool);
    runExactAllocationCase(&fixture, 5, small_size + 5U, kExpectedExactSmall, false);
    runExactAllocationCase(&fixture, 5, small_size + 6U, kExpectedExactLarge, false);
    runExactAllocationCase(&fixture, 0, small_size, kExpectedExactSmall, false);
    runExactAllocationCase(&fixture, 0, small_size + 1U, kExpectedExactLarge, false);
    const uint32_t large_size = bufferpoolGetLargeBufferSize(fixture.pool);
    runExactAllocationCase(&fixture, u, large_size + u, kExpectedExactLarge, false);
    runExactAllocationCase(&fixture, u, large_size + u + 1U, kExpectedExactGrown, false);
    poolFixtureDestroy(&fixture);

    fixture    = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 0);
    small_size = bufferpoolGetSmallBufferSize(fixture.pool);
    runExactAllocationCase(&fixture, u, small_size + u, kExpectedExactLarge, false);
    poolFixtureDestroy(&fixture);
}

typedef struct overflow_shared_state_s
{
    buffer_stream_t stream;
    sbuf_t         *entries[4];
    uint32_t        reached_push;
} overflow_shared_state_t;

static void *mapSharedTestMemory(size_t bytes)
{
    void *memory = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    require(memory != MAP_FAILED, "failed to allocate shared overflow-test memory");
    memoryZero(memory, bytes);
    return memory;
}

static sbuf_t *mapSharedTestBuffer(uint32_t payload_capacity, uint16_t left_padding, uint8_t value)
{
    const uint32_t capacity    = payload_capacity + left_padding;
    sbuf_t        *buffer      = mapSharedTestMemory(sizeof(sbuf_t) + capacity);
    buffer->curpos             = left_padding;
    buffer->len                = 1;
    buffer->capacity           = capacity;
    buffer->l_pad              = left_padding;
    buffer->is_temporary       = false;
    buffer->lifetime           = NULL;
    *sbufGetMutablePtr(buffer) = value;
    return buffer;
}

static void runPushOverflowInvariant(bool coalescing)
{
    pool_fixture_t fixture          = poolFixtureCreate(kTestLargeBufferSize, kTestSmallBufferSize, 64, 64);
    const uint32_t payload_capacity = bufferpoolGetSmallBufferSize(fixture.pool);
    const uint16_t left_padding     = bufferpoolGetSmallBufferPadding(fixture.pool);
    const size_t   buffer_map_size  = sizeof(sbuf_t) + payload_capacity + left_padding;

    overflow_shared_state_t *state  = mapSharedTestMemory(sizeof(*state));
    sbuf_t                  *tail   = mapSharedTestBuffer(payload_capacity, left_padding, 0x11);
    sbuf_t                  *source = mapSharedTestBuffer(payload_capacity, left_padding, 0x22);
    state->entries[0]               = tail;
    state->stream.pool              = fixture.pool;
    state->stream.q                 = (bs_doublequeue_t) {
                        .cbuf    = state->entries,
                        .start   = 0,
                        .end     = 1,
                        .capmask = ARRAY_SIZE(state->entries) - 1U,
    };
    state->stream.size             = UINT32_MAX;
    state->stream.use_left_padding = 0;

    pid_t child = fork();
    require(child >= 0, "failed to fork push-overflow invariant child");
    if (child == 0)
    {
        state->reached_push = 1;
        if (coalescing)
        {
            bufferstreamPushCoalescing(&state->stream, source);
        }
        else
        {
            bufferstreamPush(&state->stream, source);
        }
        _Exit(kChildReturned);
    }

    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for push-overflow invariant child");
    require(state->reached_push == 1, "push-overflow child did not reach the operation under test");
    require(WIFEXITED(status) && WEXITSTATUS(status) == 1,
            "push overflow did not fail fast with the documented status");
    require(state->stream.size == UINT32_MAX && state->stream.q.start == 0 && state->stream.q.end == 1 &&
                state->entries[0] == tail && state->entries[1] == NULL,
            "push overflow mutated queue or aggregate size before aborting");
    require(sbufGetLength(tail) == 1 && *(const uint8_t *) sbufGetRawPtr(tail) == 0x11 &&
                ((const uint8_t *) sbufGetRawPtr(tail))[1] == 0 && sbufGetLength(source) == 1 &&
                *(const uint8_t *) sbufGetRawPtr(source) == 0x22,
            "push overflow mutated source or tail before aborting");

    require(munmap(tail, buffer_map_size) == 0 && munmap(source, buffer_map_size) == 0 &&
                munmap(state, sizeof(*state)) == 0,
            "failed to release shared overflow-test memory");
    poolFixtureDestroy(&fixture);
}

static void testCoalescingOverflowAbortsBeforeSuccess(void)
{
    runPushOverflowInvariant(false);
    runPushOverflowInvariant(true);
}

typedef void (*invalid_view_case_t)(buffer_pool_t *pool);

static void requireInvalidViewAborts(buffer_pool_t *pool, invalid_view_case_t test_case, const char *message)
{
    pid_t child = fork();
    require(child >= 0, "failed to fork a byte-view invariant child");

    if (child == 0)
    {
        test_case(pool);
        _Exit(kChildReturned);
    }

    int status = 0;
    require(waitpid(child, &status, 0) == child, "failed to wait for a byte-view invariant child");
    require(WIFEXITED(status), message);
    require(WEXITSTATUS(status) == 1, message);
}

static void viewNullStream(buffer_pool_t *pool)
{
    discard pool;
    discard bufferstreamViewByteAt(NULL, 0);
}

static void viewAtStreamEnd(buffer_pool_t *pool)
{
    buffer_stream_t stream = bufferstreamCreate(pool, 0);
    sbuf_t         *buf    = sbufCreate(1);
    sbufSetLength(buf, 1);
    bufferstreamPush(&stream, buf);
    discard bufferstreamViewByteAt(&stream, 1);
}

static void viewWithInconsistentSize(buffer_pool_t *pool)
{
    buffer_stream_t stream = bufferstreamCreate(pool, 0);
    sbuf_t         *buf    = sbufCreate(1);
    sbufSetLength(buf, 1);
    bufferstreamPush(&stream, buf);
    stream.size = 2;
    discard bufferstreamViewByteAt(&stream, 1);
}

static void testInvalidViewsAbort(buffer_pool_t *pool)
{
    requireInvalidViewAborts(pool, viewNullStream, "a NULL byte-view stream did not abort with status 1");
    requireInvalidViewAborts(pool, viewAtStreamEnd, "an out-of-range byte view did not abort with status 1");
    requireInvalidViewAborts(
        pool, viewWithInconsistentSize, "inconsistent byte-view size accounting did not abort with status 1");
}

int main(void)
{
    master_pool_t *large_master = masterpoolCreateWithCapacity(16);
    master_pool_t *small_master = masterpoolCreateWithCapacity(16);
    buffer_pool_t *pool         = bufferpoolCreate(large_master, small_master, 8, 256, 64);
    bufferpoolUpdateAllocationPaddings(pool, 64, 64);

    testDuplicateToCopiesCompleteSource();
    testDuplicateToRejectsCursorPastCapacity();
    testDuplicateToRejectsIncompletePayload();
    testDuplicateToAcceptsEmptyExactEndCursor();
    testDuplicatePreservesCompleteSource();
    testPooledDuplicateHandlesConsumedPadding(pool);
    testViewByteAcrossQueuedBuffers(pool);
    testInvalidViewsAbort(pool);

    testOrdinaryPushCompatibility();
    testCoalescingOneByteFragmentsAndDequeBack();
    testCoalescingCopyAndInputBoundaries();
    testCoalescingConsumedTailAndFitPolicy();
    testCoalescingReadApisAndViews();
    testCoalescingImmediatePoolSettlement();
    testCoalescingLifetimeExclusions();
    testCoalescingTemporaryAndZeroExclusions();
    testPaddingAwareExactReadAllocation();
    testCoalescingOverflowAbortsBeforeSuccess();

    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);

    puts("bufio contract tests passed");
    return 0;
}
