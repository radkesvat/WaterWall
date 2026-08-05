#include "wwapi.h"

#include <sys/wait.h>
#include <unistd.h>

enum
{
    kChildReturned = 66
};

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

    bufferpoolDestroy(pool);
    masterpoolMakeEmpty(large_master);
    masterpoolMakeEmpty(small_master);
    masterpoolDestroy(large_master);
    masterpoolDestroy(small_master);

    puts("bufio contract tests passed");
    return 0;
}
