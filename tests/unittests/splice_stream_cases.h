#include "splice_stream.h"
#if WW_HAVE_SPLICE
#include <fcntl.h>
#endif

#if WW_HAVE_SPLICE
static bool     streamProbe;
static unsigned streamTransferFault;
static size_t   streamReadBytes;
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
    if (streamProbe && streamTransferFault == 2)
        count = min(count, (size_t) 1);
    return __real_splice(source, source_offset, target, target_offset, count, flags);
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

static void testSpliceStreamContracts(void)
{
    pool_fixture_t f = poolFixtureCreate(32768, 4096, 64, 64);

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
