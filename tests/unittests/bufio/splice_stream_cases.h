/*
 * Covers: splice stream cases; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Opt-in fixture/header composition. The including suite owns setup, case publication, and
 * cleanup; this header has no independent CTest entry.
 * CTest: Shared header; see the including suite for execution.
 */
#include "splice_stream.h"
#if WW_HAVE_SPLICE
#include <fcntl.h>
#endif

#if WW_HAVE_SPLICE
static bool     streamProbe;
static unsigned streamTransferFault;
static size_t   streamReadBytes;
static size_t   streamSpliceBytes;
ssize_t         __real_read(int fd, void *buffer, size_t count);
ssize_t         __wrap_read(int fd, void *buffer, size_t count);
ssize_t __real_splice(int source, off_t *source_offset, int target, off_t *target_offset, size_t count, unsigned flags);
ssize_t __wrap_splice(int source, off_t *source_offset, int target, off_t *target_offset, size_t count, unsigned flags);
ssize_t __wrap_read(int fd, void *buffer, size_t count)
{
    ssize_t n = __real_read(fd, buffer, count);
    if (streamProbe && n > 0)
        streamReadBytes += (size_t) n;
    return n;
}
ssize_t __wrap_splice(int source, off_t *source_offset, int target, off_t *target_offset, size_t count, unsigned flags)
{
    if (streamProbe && streamTransferFault == 1)
    {
        streamTransferFault = 2;
        errno               = EINTR;
        return -1;
    }
    if (streamProbe && streamTransferFault == 3)
    {
        streamTransferFault = 0;
        errno               = EAGAIN;
        return -1;
    }
    if (streamProbe && streamTransferFault == 4)
    {
        streamTransferFault = 0;
        errno               = EINVAL;
        return -1;
    }
    if (streamProbe && streamTransferFault == 5)
    {
        streamTransferFault = 4;
        count               = min(count, (size_t) 1);
    }
    if (streamProbe && streamTransferFault == 2)
        count = min(count, (size_t) 1);
    const ssize_t n = __real_splice(source, source_offset, target, target_offset, count, flags);
    if (streamProbe && n > 0)
        streamSpliceBytes += (size_t) n;
    return n;
}
#endif

static sbuf_t *streamTestBytes(buffer_pool_t *pool, const void *bytes, uint32_t count)
{
    sbuf_t *b = bufferpoolGetBestFit(pool, count, bufferpoolGetLargeBufferPadding(pool));
    sbufSetLength(b, count);
    memoryCopy(sbufGetMutablePtr(b), bytes, count);
    return b;
}

static void streamCheckBytes(buffer_pool_t *pool, sbuf_t *b, const void *expected, uint32_t count)
{
    require(sbufGetLength(b) == count, "frame body length changed");
    require(sbufGetLeftCapacity(b) >= bufferpoolGetLargeBufferPadding(pool), "frame lost onward headroom");
    if ((b->flags & kSbufFlagSplice) != 0)
    {
        sbuf_t *ordinary = bufferpoolGetBestFit(pool, count, bufferpoolGetLargeBufferPadding(pool));
        sbufSpliceReadToBuffer(b, ordinary, count);
        bufferpoolReuseBuffer(pool, b);
        b = ordinary;
    }
    require(memoryEqual(sbufGetRawPtr(b), expected, count), "frame body order/content changed");
    bufferpoolReuseBuffer(pool, b);
}

static void streamCheckCharge(const splice_stream_t *s)
{
    size_t pending_charge = 0;
    c_foreach(entry, ww_sbuffer_queue_t, s->pending.q) pending_charge += sbufGetQueueCharge(*entry.ref);
    require(bufferqueueGetCharge(&s->pending) == pending_charge, "stream mutation left stale pending queue charge");
    size_t charge = (s->head == NULL ? 0 : sbufGetQueueCharge(s->head)) + pending_charge;
    require(charge == splicestreamCharge(s), "active-head mutation left stale stream charge");
}

static void testSpliceStreamDiscard(buffer_pool_t *pool)
{
    const uint8_t wire[] = "HEADER01bodyHEADER02tailHEADER03";
    for (unsigned mode = 0; mode < (WW_HAVE_SPLICE ? 4U : 1U); ++mode)
        for (uint32_t split = 0; split < sizeof(wire); ++split)
        {
            splice_stream_t *s = splicestreamCreate(pool, 8);
            for (unsigned part = 0; part < 2; ++part)
            {
                const uint32_t offset = part ? split : 0;
                const uint32_t count  = part ? sizeof(wire) - 1U - split : split;
                sbuf_t        *input;
#if WW_HAVE_SPLICE
                if (mode == 1 || mode == 2 || (mode == 3 && part != 0))
                {
                    const uint32_t prefix = mode == 2 ? min(count, 11U) : 0;
                    input = makeSpliceTestBuffer(pool, wire + offset, prefix, wire + offset + prefix, count - prefix);
                }
                else
#endif
                    input = streamTestBytes(pool, wire + offset, count);
                require(splicestreamPush(s, input), "discard stream push refused");
            }
            splicestreamDiscardFrame(s, 4);
            streamCheckCharge(s);
            require(splicestreamLength(s) == 20 && memoryEqual(splicestreamPeekHeader(s), "HEADER02", 8),
                    "discard consumed the next frame's header or body");
            streamCheckBytes(pool, splicestreamMoveFrame(s, NULL, 4), "tail", 4);
            require(memoryEqual(splicestreamPeekHeader(s), "HEADER03", 8), "discard lost a later header");
            splicestreamDiscardFrame(s, 0);
            require(splicestreamLength(s) == 0 && splicestreamCharge(s) == 0,
                    "zero-body discard left frame bytes or charge");
            splicestreamDestroy(s);
        }

#if WW_HAVE_SPLICE
    /* Exact pipe ranges must stay in the kernel, even after short progress and
     * EINTR. Reading the suffix independently detects over-discard. */
    for (unsigned fault = 0; fault < 6; ++fault)
    {
        if (fault == 2)
            continue;
        splice_stream_t *s         = splicestreamCreate(pool, 0);
        sbuf_t          *source    = makeSpliceTestBuffer(pool, NULL, 0, (const uint8_t *) "abcdef", 6);
        const int        source_fd = sbufSpliceMetadata(source).pipefd[0];
        require(splicestreamPush(s, source), "discard source push failed");
        streamProbe         = true;
        streamTransferFault = fault;
        streamReadBytes     = 0;
        streamSpliceBytes   = 0;
        splicestreamDiscardFrame(s, 3);
        streamProbe                = false;
        streamTransferFault        = 0;
        const size_t expected_read = fault == 5 ? 2U : (fault >= 3 ? 3U : 0U);
        require(streamReadBytes == expected_read && streamSpliceBytes == 3U - expected_read,
                "discard used the wrong fast/fallback path");
        streamCheckCharge(s);
        require(splicestreamLength(s) == 3 && splicestreamCharge(s) == sbufGetQueueCharge(source),
                "partial discard corrupted stream length or charge");
        sbuf_t *suffix = splicestreamMoveFrame(s, bufferpoolGetSpliceBuffer(pool), 3);
        require(suffix == source && sbufSpliceMetadata(suffix).pipefd[0] == source_fd,
                "partial discard replaced its source pipe");
        const int discard_fd = s->discard_fd;
        if (discard_fd >= 0)
            require((fcntl(discard_fd, F_GETFD) & FD_CLOEXEC) != 0, "discard descriptor is not close-on-exec");
        splicestreamDestroy(s);
        if (discard_fd >= 0)
            require(fcntl(discard_fd, F_GETFD) == -1 && errno == EBADF, "discard descriptor leaked at destroy");
        streamCheckBytes(pool, suffix, "def", 3);
    }

    /* Fully consumed wrappers keep their now-empty pipes reusable. A following
     * frame/header in another pipe is preserved while only its header is read. */
    splice_stream_t *s      = splicestreamCreate(pool, 8);
    sbuf_t          *source = makeSpliceTestBuffer(pool, (const uint8_t *) "HEADER01a", 9, (const uint8_t *) "bcd", 3);
    const int        source_fd = sbufSpliceMetadata(source).pipefd[0];
    require(splicestreamPush(s, source), "full discard source push failed");
    require(splicestreamPush(s, makeSpliceTestBuffer(pool, NULL, 0, (const uint8_t *) "HEADER02tail", 12)),
            "next discard frame push failed");
    streamProbe       = true;
    streamReadBytes   = 0;
    streamSpliceBytes = 0;
    splicestreamDiscardFrame(s, 4);
    streamProbe = false;
    require(streamSpliceBytes == 3 && streamReadBytes == 8, "discard materialized body bytes or skipped next header");
    int queued_bytes = -1;
    require(ioctl(source_fd, FIONREAD, &queued_bytes) == 0 && queued_bytes == 0,
            "full discard did not preserve an empty reusable source pipe");
    streamCheckBytes(pool, splicestreamMoveFrame(s, NULL, 4), "tail", 4);
    splicestreamDestroy(s);

    /* Claimed bytes are already owned by a private pipe; absent bytes must not
     * turn into an incomplete frame that is silently accepted. */
    const pid_t child = fork();
    require(child >= 0, "failed to fork discard invariant child");
    if (child == 0)
    {
        s      = splicestreamCreate(pool, 0);
        source = makeSpliceTestBuffer(pool, NULL, 0, (const uint8_t *) "ab", 2);
        source->len += 1;
        source->capacity += 1;
        require(splicestreamPush(s, source), "incomplete discard pipe push failed");
        splicestreamDiscardFrame(s, 3);
        _Exit(kChildReturned);
    }
    int status = 0;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 1,
            "discard accepted missing private-pipe bytes");
#endif
}

#if WW_HAVE_SPLICE
static void testSpliceStreamResidentRanges(void)
{
    /* Extra splice padding keeps the whole-wrapper fast path eligible even
     * when every requested byte is in a resident prefix. */
    pool_fixture_t f      = poolFixtureCreate(32768, 4096, 64, 128);
    const uint8_t  wire[] = "HEADordinaryPIPE";
    for (uint32_t leading = 0; leading <= 4; leading += 4)
        for (uint32_t pipe_bytes = 0; pipe_bytes <= 4; pipe_bytes += 4)
            for (uint32_t count = 0; count <= leading + 8 + pipe_bytes; ++count)
            {
                splice_stream_t *s = splicestreamCreate(f.pool, 0);
                if (leading != 0)
                    require(splicestreamPush(s, streamTestBytes(f.pool, wire, leading)), "resident head push failed");
                require(splicestreamPush(s, makeSpliceTestBuffer(f.pool, wire + 4, 8, wire + 12, pipe_bytes)),
                        "resident prefix push failed");
                sbuf_t *body = splicestreamMoveFrame(s, bufferpoolGetSpliceBuffer(f.pool), count);
                require(sbufIsSplice(body) == (count > leading + 8),
                        "frame representation used pipe bytes outside the requested range");
                streamCheckBytes(f.pool, body, wire + 4 - leading, count);
                streamCheckCharge(s);
                const uint32_t remaining = leading + 8 + pipe_bytes - count;
                require(splicestreamLength(s) == remaining, "resident extraction consumed its suffix");
                streamCheckBytes(
                    f.pool, splicestreamMoveFrame(s, NULL, remaining), wire + 4 - leading + count, remaining);
                require(splicestreamLength(s) == 0 && splicestreamCharge(s) == 0,
                        "resident extraction left bytes or charge");
                splicestreamDestroy(s);
            }
    poolFixtureDestroy(&f);
}
#endif

static void testSpliceStreamContracts(void)
{
#if WW_HAVE_SPLICE
    testSpliceStreamResidentRanges();
#endif
    pool_fixture_t f = poolFixtureCreate(32768, 4096, 64, 64);
    testSpliceStreamDiscard(f.pool);

    const uint8_t wire[] = "HEADER01bodyNEXTHEADtail";
    for (unsigned mode = 0; mode < (WW_HAVE_SPLICE ? 3U : 1U); ++mode)
        for (uint32_t split = 0; split <= 12; ++split)
        {
            splice_stream_t *s = splicestreamCreate(f.pool, 8);
            for (unsigned part = 0; part < 2; ++part)
            {
                const uint32_t offset = part ? split : 0;
                const uint32_t count  = part ? sizeof(wire) - 1U - split : split;
                sbuf_t        *input;
#if WW_HAVE_SPLICE
                if (mode != 0)
                {
                    const uint32_t prefix = mode == 2 ? min(count, 3U) : 0;
                    input = makeSpliceTestBuffer(f.pool, wire + offset, prefix, wire + offset + prefix, count - prefix);
                }
                else
#endif
                    input = streamTestBytes(f.pool, wire + offset, count);
                require(splicestreamPush(s, input), "stream push refused");
                streamCheckCharge(s);
                if (! part)
                {
                    require(splicestreamLength(s) == count, "partial header length changed");
                    require(splicestreamBodyBytes(s) == (count < 8 ? 0 : count - 8), "partial body count wrong");
                }
            }
            for (unsigned i = 0; i < 10; ++i)
                require(memoryEqual(splicestreamPeekHeader(s), wire, 8), "cached header changed on peek");
            sbuf_t *body = splicestreamMoveFrame(s, bufferpoolGetSpliceBuffer(f.pool), 4);
            streamCheckBytes(f.pool, body, "body", 4);
            streamCheckCharge(s);
            require(memoryEqual(splicestreamPeekHeader(s), "NEXTHEAD", 8) && splicestreamBodyBytes(s) == 4,
                    "body was prefetched as next header");
            body = bufferpoolGetBestFit(f.pool, 4, 64);
            splicestreamMoveFrameToOrdinary(s, body, 4);
            streamCheckBytes(f.pool, body, "tail", 4);
            require(splicestreamLength(s) == 0 && splicestreamCharge(s) == 0, "frame left bytes or stream charge");
            splicestreamDestroy(s);
        }
    /* A failed/uninitialized preferred pipe is a complete ordinary fallback,
     * including unsupported builds; the source suffix remains independently owned. */
    sbuf_t *plain_source  = streamTestBytes(f.pool, "abcd", 4);
    sbuf_t *uninitialized = sbufCreateSplice(64);
    sbuf_t *fallback      = sbufMoveRangeTo(f.pool, plain_source, uninitialized, 2, 2, 64);
    streamCheckBytes(f.pool, fallback, "ab", 2);
    streamCheckBytes(f.pool, plain_source, "cd", 2);

    /* Header-only frames advance once, empty pushes never manufacture frames. */
    splice_stream_t *s = splicestreamCreate(f.pool, 8);
    require(splicestreamPush(s, streamTestBytes(f.pool, "HEADER01HEADER02", 16)), "zero-body push failed");
    streamCheckBytes(f.pool, splicestreamMoveFrame(s, NULL, 0), "", 0);
    require(memoryEqual(splicestreamPeekHeader(s), "HEADER02", 8), "zero-body frame did not advance header");
    streamCheckBytes(f.pool, splicestreamMoveFrame(s, NULL, 0), "", 0);
    splicestreamDestroy(s);

#if WW_HAVE_SPLICE
    /* One source pipe split into independently owned body results. */
    s                   = splicestreamCreate(f.pool, 0);
    sbuf_t   *source    = makeSpliceTestBuffer(f.pool, NULL, 0, (const uint8_t *) "ABCDEF", 6);
    const int source_fd = sbufSpliceMetadata(source).pipefd[0];
    require(splicestreamPush(s, source), "split source push failed");
    const long page_size = sysconf(_SC_PAGESIZE);
    require(page_size > 0 && page_size <= INT_MAX / 4, "invalid test host page size");
    sbuf_t *split_destination = bufferpoolGetSpliceBuffer(f.pool);
    require(fcntl(sbufSpliceMetadata(split_destination).pipefd[1], F_SETPIPE_SZ, (int) (4 * page_size)) >=
                4 * page_size,
            "cannot reserve slots for the positive-short-transfer fixture");
    streamProbe         = true;
    streamTransferFault = 1;
    streamReadBytes     = 0;
    sbuf_t *a           = splicestreamMoveFrame(s, split_destination, 3);
    streamProbe         = false;
    streamTransferFault = 0;
    require(streamReadBytes == 0, "short/EINTR split materialized body bytes");
    require((a->flags & kSbufFlagSplice) != 0 && sbufSpliceMetadata(a).pipefd[0] != source_fd,
            "partial source did not move into an independent private pipe");
    streamCheckCharge(s);
    require(splicestreamCharge(s) == sbufGetQueueCharge(source), "partial pipe consumption was charged twice");
    sbuf_t *b = splicestreamMoveFrame(s, bufferpoolGetSpliceBuffer(f.pool), 3);
    streamCheckCharge(s);
    require(b == source, "whole body did not transfer its original wrapper");
    splicestreamDestroy(s);
    streamCheckBytes(f.pool, b, "DEF", 3);
    streamCheckBytes(f.pool, a, "ABC", 3);

    /* Real Linux slot exhaustion: one byte from A occupies the only destination
     * slot. B cannot enter that pipe despite its nominal free byte capacity. */
    for (unsigned pressure = 0; pressure < 2; ++pressure)
    {
        s = splicestreamCreate(f.pool, 0);
        require(splicestreamPush(s, makeSpliceTestBuffer(f.pool, NULL, 0, (const uint8_t *) "A", 1)), "A push failed");
        require(splicestreamPush(s, makeSpliceTestBuffer(f.pool, NULL, 0, (const uint8_t *) "BC", 2)), "B push failed");
        sbuf_t   *dest      = bufferpoolGetSpliceBuffer(f.pool);
        const int fd        = sbufSpliceMetadata(dest).pipefd[1];
        const int pipe_size = (int) ((pressure ? 1 : 2) * page_size);
        require(fcntl(fd, F_SETPIPE_SZ, pipe_size) >= pipe_size, "cannot set pipe slots");
        streamReadBytes = 0;
        streamProbe     = true;
        a               = splicestreamMoveFrame(s, dest, 2);
        streamProbe     = false;
        require(streamReadBytes == (pressure ? 2U : 0U), "merge/fallback read wrong number of body bytes");
        require(((a->flags & kSbufFlagSplice) == 0) == (pressure != 0), "pipe pressure chose wrong representation");
        streamCheckBytes(f.pool, a, "AB", 2);
        streamCheckBytes(f.pool, splicestreamMoveFrame(s, NULL, 1), "C", 1);
        splicestreamDestroy(s);
    }
    for (unsigned refusal = 0; refusal < 3; ++refusal)
    {
        s      = splicestreamCreate(f.pool, 0);
        source = makeSpliceTestBuffer(f.pool, NULL, 0, (const uint8_t *) "ABCD", 4);
        if (refusal == 2)
        {
            splice_buffer_metadata_t metadata = sbufSpliceMetadata(source);
            metadata.pipe_capacity            = 0;
            sbufSpliceSetMetadata(source, metadata);
        }
        require(splicestreamPush(s, source), "fallback source push failed");
        streamTransferFault = refusal == 0 ? 3 : 0;
        streamProbe         = true;
        a                   = splicestreamMoveFrame(s, refusal == 1 ? NULL : bufferpoolGetSpliceBuffer(f.pool), 2);
        streamProbe         = false;
        require(sbufIsSplice(a) == (refusal == 2),
                "destination pressure or unknown source capacity chose wrong representation");
        streamCheckBytes(f.pool, a, "AB", 2);
        streamCheckBytes(f.pool, splicestreamMoveFrame(s, NULL, 2), "CD", 2);
        splicestreamDestroy(s);
    }
    /* No automatic worker quota: pressure compaction is explicit and beneficial. */
    s = splicestreamCreate(f.pool, 0);
    for (unsigned i = 0; i < 160; ++i)
        require(splicestreamPush(s, makeSpliceTestBuffer(f.pool, NULL, 0, (const uint8_t *) "x", 1)),
                "tiny push failed");
    require(bufferqueueGetBufCount(&s->pending) == 159, "retention silently converted pipes");
    size_t before   = splicestreamCharge(s);
    streamProbe     = true;
    streamReadBytes = 0;
    require(splicestreamCompact(s) && splicestreamCharge(s) < before && streamReadBytes == 160,
            "beneficial explicit compaction failed");
    streamProbe = false;
    a           = splicestreamMoveFrame(s, NULL, 160);
    for (unsigned i = 0; i < 160; ++i)
        require(((uint8_t *) sbufGetRawPtr(a))[i] == 'x', "pressure compaction reordered bytes");
    bufferpoolReuseBuffer(f.pool, a);
    require(splicestreamCharge(s) == 0, "compacted stream charge did not settle");
    splicestreamDestroy(s);

#endif
    poolFixtureDestroy(&f);
}
