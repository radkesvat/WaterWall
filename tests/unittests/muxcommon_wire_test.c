#include "MuxCommon/mux_limits.h"
#include "MuxCommon/mux_parent_output.h"
#include "MuxCommon/mux_retention.h"
#include "MuxCommon/mux_wire.h"
#include "wwapi.h"

#if WW_HAVE_SPLICE
#include <fcntl.h>
#include <unistd.h>
#endif

enum
{
    kTestCid             = 0x12345678U,
    kTestLargeBufferSize = 1024U * 1024U + 64U,
    kTestPoolCapacity    = 16
};

typedef struct test_pool_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    master_pool_t *medium_master;
    master_pool_t *splice_master;
    buffer_pool_t *pool;
} test_pool_t;

typedef struct frame_view_s
{
    uint8_t        flags;
    uint32_t       cid;
    uint32_t       length;
    const uint8_t *data;
} frame_view_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "ASSERT FAILED: %s\n", message);
        exit(1);
    }
}

static test_pool_t testPoolCreateWithSizes(uint32_t large_size, uint32_t medium_size, uint16_t splice_padding)
{
    test_pool_t result = {
        .large_master  = masterpoolCreateWithCapacity(kTestPoolCapacity),
        .small_master  = masterpoolCreateWithCapacity(kTestPoolCapacity),
        .medium_master = masterpoolCreateWithCapacity(kTestPoolCapacity),
        .splice_master = masterpoolCreateWithCapacity(kTestPoolCapacity),
        .pool          = NULL,
    };
    require(result.large_master != NULL && result.small_master != NULL, "failed to create master pools");

    result.pool = bufferpoolCreate(result.large_master,
                                   result.medium_master,
                                   result.small_master,
                                   result.splice_master,
                                   kTestPoolCapacity,
                                   large_size,
                                   medium_size,
                                   1024);
    require(result.pool != NULL, "failed to create buffer pool");
    bufferpoolUpdateAllocationPaddings(
        result.pool, kMuxFrameLength * 2U, kMuxFrameLength * 2U, kMuxFrameLength * 2U, splice_padding);
    return result;
}

static void testPoolDestroy(test_pool_t *test_pool)
{
    bufferpoolDestroy(test_pool->pool);
    masterpoolMakeEmpty(test_pool->large_master);
    masterpoolMakeEmpty(test_pool->small_master);
    masterpoolMakeEmpty(test_pool->medium_master);
    masterpoolMakeEmpty(test_pool->splice_master);
    masterpoolDestroy(test_pool->large_master);
    masterpoolDestroy(test_pool->small_master);
    masterpoolDestroy(test_pool->medium_master);
    masterpoolDestroy(test_pool->splice_master);
}

static uint8_t patternByte(uint32_t index)
{
    return (uint8_t) ((index * 31U + 17U) & 0xFFU);
}

static sbuf_t *makePayload(buffer_pool_t *pool, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetBestFit(pool, length, bufferpoolGetLargeBufferPadding(pool));
    sbufSetLength(buf, length);

    uint8_t *bytes = sbufGetMutablePtr(buf);
    for (uint32_t i = 0; i < length; ++i)
    {
        bytes[i] = patternByte(i);
    }
    return buf;
}

#if WW_HAVE_SPLICE
static sbuf_t *makeSplicePattern(buffer_pool_t *pool, uint32_t length)
{
    require(length <= 4096, "direct splice test payload is too large");
    sbuf_t *input = bufferpoolGetSpliceBuffer(pool);
    require(input != NULL, "could not allocate splice payload");

    uint8_t bytes[4096];
    for (uint32_t i = 0; i < length; ++i)
        bytes[i] = patternByte(i);

    const splice_buffer_metadata_t metadata = sbufSpliceMetadata(input);
    uint32_t                       written  = 0;
    while (written < length)
    {
        ssize_t result = write(metadata.pipefd[1], bytes + written, length - written);
        if (result < 0 && errno == EINTR)
            continue;
        require(result > 0, "could not populate splice payload pipe");
        written += (uint32_t) result;
    }

    input->capacity = input->l_pad + length;
    sbufSetLength(input, length);
    return input;
}

static sbuf_t *makeLargeSplicePattern(buffer_pool_t *pool, uint32_t length)
{
    sbuf_t *input = bufferpoolGetSpliceBuffer(pool);
    require(input != NULL, "could not allocate large splice payload");
    const uint32_t resident = length > kMuxMaxDataFrameLength ? length - kMuxMaxDataFrameLength : 0;
    require(resident <= 16, "large fixture prefix exceeds real headroom");
    const uint32_t body = length - resident;
    require(sbufSpliceInitPipe(input, body) == 0, "could not initialize the large splice test pipe");
    const splice_buffer_metadata_t metadata = sbufSpliceMetadata(input);
    const int                      capacity = fcntl(metadata.pipefd[0], F_GETPIPE_SZ);
    require(capacity >= 0 && (uint32_t) capacity >= body,
            "test environment cannot hold the complete large payload in one nonblocking private pipe");
    uint8_t  bytes[4096];
    uint32_t offset = 0;
    while (offset < body)
    {
        const uint32_t count = min(body - offset, (uint32_t) sizeof(bytes));
        for (uint32_t i = 0; i < count; ++i)
            bytes[i] = patternByte(resident + offset + i);
        const ssize_t n = write(metadata.pipefd[1], bytes, count);
        if (n < 0 && errno == EINTR)
            continue;
        require(n > 0, "could not preload the complete large private-pipe payload");
        offset += (uint32_t) n;
    }
    /* Publish only after every claimed byte is owned, exactly like NIO. */
    input->capacity = input->l_pad + body;
    sbufSetLength(input, body);
    sbufShiftLeft(input, resident);
    for (uint32_t i = 0; i < resident; ++i)
        sbufGetMutablePtr(input)[i] = patternByte(i);
    return input;
}

static void requireSpliceBody(buffer_pool_t *pool, sbuf_t *input, uint32_t length, const char *message)
{
    sbuf_t *resident = bufferpoolGetLargeBuffer(pool);
    resident         = sbufReserveSpace(resident, length);
    sbufSpliceMaterializeToBuffer(input, resident, pool);
    require((resident->flags & kSbufFlagSplice) == 0 && sbufGetLength(resident) == length, message);
    for (uint32_t i = 0; i < length; ++i)
        require(((const uint8_t *) sbufGetRawPtr(resident))[i] == patternByte(i), message);
    bufferpoolReuseBuffer(pool, resident);
}
#endif

static uint32_t parseFrames(const sbuf_t *encoded, frame_view_t *frames, uint32_t capacity)
{
    const uint8_t *bytes  = sbufGetRawPtr(encoded);
    const uint32_t length = sbufGetLength(encoded);
    uint32_t       offset = 0;
    uint32_t       count  = 0;

    while (offset < length)
    {
        require(length - offset >= kMuxFrameLength, "encoded data ends inside a header");
        require(count < capacity, "encoded data contains too many frames");

        mux_frame_t frame;
        muxDecodeFrameHeader(bytes + offset, &frame);
        offset += kMuxFrameLength;

        const uint32_t payload_length = frame.length;
        require(length - offset >= payload_length, "encoded data ends inside a payload");

        frames[count++] =
            (frame_view_t) {.flags = frame.flags, .cid = frame.cid, .length = payload_length, .data = bytes + offset};
        offset += payload_length;
    }
    return count;
}

static void requirePayload(const frame_view_t *frames, uint32_t count, uint32_t first_data_frame,
                           uint32_t expected_length)
{
    uint32_t consumed = 0;
    for (uint32_t i = first_data_frame; i < count; ++i)
    {
        require(frames[i].flags == kMuxFlagData, "payload fragment has the wrong flag");
        require(frames[i].cid == kTestCid, "payload fragment has the wrong cid");
        require(frames[i].length <= kMuxMaxDataFrameLength, "payload fragment exceeds the wire limit");

        for (uint32_t j = 0; j < frames[i].length; ++j)
        {
            require(frames[i].data[j] == patternByte(consumed + j), "payload bytes were not preserved");
        }
        consumed += frames[i].length;
    }
    require(consumed == expected_length, "fragmented payload has the wrong total length");
}

static void testEveryHeaderFlag(void)
{
    const uint32_t lengths[] = {0, 1, 65527, 65535, 65536, kMuxMaxDataFrameLength - 1, kMuxMaxDataFrameLength};
    const uint32_t cids[]    = {0, kTestCid, 0x80000000U, UINT32_MAX};
    require(kMuxFrameLength == 8 && kMuxMaxDataFrameLength == 1048576, "wire constants depend on storage geometry");
    for (unsigned flag = kMuxFlagOpen; flag <= kMuxFlagData; ++flag)
        for (size_t i = 0; i < ARRAY_SIZE(lengths); ++i)
            for (size_t j = 0; j < ARRAY_SIZE(cids); ++j)
            {
                mux_wire_header_t wire;
                muxSetMuxFrameHeader(&wire, lengths[i], cids[j], (uint8_t) flag);
                const uint8_t expected[] = {(uint8_t) (lengths[i] >> 16),
                                            (uint8_t) (lengths[i] >> 8),
                                            (uint8_t) lengths[i],
                                            (uint8_t) flag,
                                            (uint8_t) (cids[j] >> 24),
                                            (uint8_t) (cids[j] >> 16),
                                            (uint8_t) (cids[j] >> 8),
                                            (uint8_t) cids[j]};
                require(memcmp(wire.bytes, expected, 8) == 0, "wire field offsets or byte order changed");
                uint8_t unaligned[9];
                memoryCopy(unaligned + 1, wire.bytes, 8);
                mux_frame_t frame;
                muxDecodeFrameHeader(unaligned + 1, &frame);
                require(frame.length == lengths[i] && frame.cid == cids[j] && frame.flags == flag,
                        "unaligned header decoding failed");
            }
    const uint8_t literal[][8] = {{1, 0, 0, 4, 0x12, 0x34, 0x56, 0x78}, {0x10, 0, 0, 4, 0x12, 0x34, 0x56, 0x78}};
    for (unsigned i = 0; i < 2; ++i)
    {
        mux_wire_header_t wire;
        muxSetMuxFrameHeader(&wire, i ? 1048576 : 65536, kTestCid, kMuxFlagData);
        require(memcmp(wire.bytes, literal[i], 8) == 0, "literal Data header mismatch");
    }
}

static void testControlAndClientSequences(buffer_pool_t *pool)
{
    static const uint8_t control_flags[] = {kMuxFlagOpen, kMuxFlagClose, kMuxFlagFlowPause, kMuxFlagFlowResume};

    for (size_t i = 0; i < ARRAY_SIZE(control_flags); ++i)
    {
        sbuf_t *control = makePayload(pool, 0);
        muxMakeMuxFrame(control, kTestCid, control_flags[i]);

        frame_view_t frames[1];
        require(parseFrames(control, frames, ARRAY_SIZE(frames)) == 1, "control frame count is not one");
        require(frames[0].flags == control_flags[i], "control frame has the wrong flag");
        require(frames[0].length == 0, "control frame is not zero length");
        require(frames[0].cid == kTestCid, "control frame has the wrong cid");
        bufferpoolReuseBuffer(pool, control);
    }

    sbuf_t *open_data = makePayload(pool, 3);
    muxMakeMuxOpenDataFrames(open_data, kTestCid);

    frame_view_t frames[2];
    require(parseFrames(open_data, frames, ARRAY_SIZE(frames)) == 2, "Open+Data did not produce two frames");
    require(frames[0].flags == kMuxFlagOpen && frames[0].length == 0, "Open+Data has an invalid Open frame");
    requirePayload(frames, 2, 1, 3);
    bufferpoolReuseBuffer(pool, open_data);

    sbuf_t *open_close = makePayload(pool, 0);
    muxMakeMuxOpenCloseFrames(open_close, kTestCid);
    require(parseFrames(open_close, frames, ARRAY_SIZE(frames)) == 2, "Open+Close did not produce two frames");
    require(frames[0].flags == kMuxFlagOpen && frames[0].length == 0, "Open+Close has an invalid Open frame");
    require(frames[1].flags == kMuxFlagClose && frames[1].length == 0, "Open+Close has an invalid Close frame");
    require(frames[0].cid == kTestCid && frames[1].cid == kTestCid, "Open+Close has the wrong cid");
    bufferpoolReuseBuffer(pool, open_close);
}

static void pushBytes(buffer_pool_t *pool, splice_stream_t *stream, const uint8_t *bytes, uint32_t length)
{
    sbuf_t *chunk = bufferpoolGetBestFit(pool, length, bufferpoolGetLargeBufferPadding(pool));
    sbufSetLength(chunk, length);
    memoryCopy(sbufGetMutablePtr(chunk), bytes, length);
    splicestreamPush(stream, chunk);
}

static void testCompleteFrameParsing(buffer_pool_t *pool)
{
    const uint8_t payload[] = {0x10, 0x20, 0x30, 0x40};
    uint8_t       wire[kMuxFrameLength + ARRAY_SIZE(payload)];
    mux_wire_header_t wire_header;
    muxSetMuxFrameHeader(&wire_header, ARRAY_SIZE(payload), kTestCid, kMuxFlagData);
    memoryCopy(wire, &wire_header, kMuxFrameLength);
    memoryCopy(wire + kMuxFrameLength, payload, ARRAY_SIZE(payload));

    splice_stream_t *stream = splicestreamCreate(pool, kMuxFrameLength);
    mux_frame_t      decoded;

    pushBytes(pool, stream, wire, kMuxFrameLength - 1U);
    require(muxPeekCompleteFrame(stream, &decoded) == kMuxPeekNeedMore, "an incomplete header was consumed");
    require(splicestreamLength(stream) == kMuxFrameLength - 1U, "incomplete header changed stream length");

    pushBytes(pool, stream, wire + kMuxFrameLength - 1U, 3U);
    require(muxPeekCompleteFrame(stream, &decoded) == kMuxPeekNeedMore, "an incomplete payload was consumed");
    require(splicestreamLength(stream) == kMuxFrameLength + 2U, "incomplete payload changed stream length");

    pushBytes(pool, stream, wire + kMuxFrameLength + 2U, 2U);
    sbuf_t *complete =
        (muxPeekCompleteFrame(stream, &decoded) == kMuxPeekReady ? muxReadFrameBody(stream, &decoded, false) : NULL);
    require(complete != NULL, "a complete fragmented frame was not returned");
    require(splicestreamLength(stream) == 0, "complete frame was not consumed exactly");
    require(decoded.length == ARRAY_SIZE(payload), "decoded frame length is wrong");
    require(decoded.flags == kMuxFlagData, "decoded frame flag is wrong");
    require(decoded.cid == kTestCid, "decoded frame cid is wrong");
    require(sbufGetLength(complete) == sizeof(payload), "returned wire frame has the wrong length");
    bufferpoolReuseBuffer(pool, complete);
    splicestreamDestroy(stream);

    stream = splicestreamCreate(pool, kMuxFrameLength);
    muxSetMuxFrameHeader(&wire_header, 0, kTestCid, kMuxFlagFlowPause);
    pushBytes(pool, stream, (const uint8_t *) &wire_header, kMuxFrameLength);
    complete =
        (muxPeekCompleteFrame(stream, &decoded) == kMuxPeekReady ? muxReadFrameBody(stream, &decoded, false) : NULL);
    require(complete != NULL, "an exact zero-length frame was not returned");
    require(decoded.length == 0 && decoded.flags == kMuxFlagFlowPause, "zero-length frame decoded incorrectly");
    bufferpoolReuseBuffer(pool, complete);
    splicestreamDestroy(stream);
}

#if WW_HAVE_SPLICE
static bool testPipeCapacity(buffer_pool_t *pool, uint32_t required, const char *name)
{
    sbuf_t    *pipe      = bufferpoolGetSpliceBuffer(pool);
    const bool available = pipe != NULL && sbufSpliceMetadata(pipe).pipe_capacity >= required;
    if (pipe != NULL)
        bufferpoolReuseBuffer(pool, pipe);
    if (! available)
        fprintf(stderr, "SKIP: %s requires a real %u-byte pipe\n", name, required);
    return available;
}

static void testSpliceMuxPaths(buffer_pool_t *pool)
{
    {
        sbuf_t *input   = makeSplicePattern(pool, 32);
        sbuf_t *encoded = NULL;
        require(muxEncodeChildPayload(pool, input, kTestCid, false, &encoded) == kMuxEncodeSuccess,
                "fitting splice payload encoding failed");
        require(encoded == input && (encoded->flags & kSbufFlagSplice) != 0,
                "fitting splice payload was unnecessarily materialized");

        mux_frame_t frame;
        muxDecodeFrameHeader(sbufGetRawPtr(encoded), &frame);
        require(frame.length == 32 && frame.flags == kMuxFlagData && frame.cid == kTestCid,
                "fitting splice payload has the wrong resident Mux header");
        sbufShiftRight(encoded, kMuxFrameLength);
        requireSpliceBody(pool, encoded, 32, "fitting splice encode changed the private-pipe body");
    }

    {
        sbuf_t *input   = makeSplicePattern(pool, 17);
        sbuf_t *encoded = NULL;
        require(muxEncodeChildPayload(pool, input, kTestCid, true, &encoded) == kMuxEncodeSuccess,
                "Open+Data splice payload encoding failed");
        require(encoded == input && (encoded->flags & kSbufFlagSplice) != 0,
                "Open+Data splice payload was unnecessarily materialized");

        mux_frame_t open_frame;
        mux_frame_t data_frame;
        muxDecodeFrameHeader(sbufGetRawPtr(encoded), &open_frame);
        muxDecodeFrameHeader((const uint8_t *) sbufGetRawPtr(encoded) + kMuxFrameLength, &data_frame);
        require(open_frame.flags == kMuxFlagOpen && open_frame.length == 0 && data_frame.flags == kMuxFlagData &&
                    data_frame.length == 17,
                "Open+Data splice payload has invalid resident headers");
        sbufShiftRight(encoded, 2U * kMuxFrameLength);
        requireSpliceBody(pool, encoded, 17, "Open+Data splice encode changed the private-pipe body");
    }

    if (testPipeCapacity(pool, kMuxMaxDataFrameLength, "large Mux splice batch"))
    {
        const uint32_t      payload_length = kMuxMaxDataFrameLength + 1U;
        sbuf_t             *input          = makeLargeSplicePattern(pool, payload_length);
        mux_parent_output_t output         = {0};

        bufferqueueInitEmpty(&output.pending);
        require(muxEncodeSpliceBatch(pool, input, kTestCid, false, &output, SIZE_MAX),
                "large splice batch encoding failed");
        require(bufferqueueGetBufCount(&output.pending) == 2, "large batch did not preserve frame boundaries");
        uint32_t offset = 0;
        while (bufferqueueGetBufCount(&output.pending) != 0)
        {
            sbuf_t *encoded = muxParentOutputPop(&output);
            encoded         = muxMaterializeRetainedPayload(pool, encoded);
            frame_view_t frame[1];
            require(parseFrames(encoded, frame, 1) == 1, "batch item has wrong frame count");
            for (uint32_t i = 0; i < frame[0].length; ++i)
                require(frame[0].data[i] == patternByte(offset++), "batch bytes changed");
            bufferpoolReuseBuffer(pool, encoded);
        }
        require(offset == payload_length && output.charge == 0, "batch lost bytes or retained queue charge");
        muxParentOutputDestroy(&output, pool);
    }

    {
        sbuf_t *retained = muxMaterializeRetainedPayload(pool, makeSplicePattern(pool, 31));
        require((retained->flags & kSbufFlagSplice) == 0 && sbufGetLength(retained) == 31,
                "paused Mux retention kept a private pipe");
        for (uint32_t i = 0; i < 31; ++i)
            require(((const uint8_t *) sbufGetRawPtr(retained))[i] == patternByte(i),
                    "paused Mux retention changed payload bytes");
        bufferpoolReuseBuffer(pool, retained);
    }

    {
        sbuf_t *wire = makeSplicePattern(pool, 41);
        muxMakeMuxFrame(wire, kTestCid, kMuxFlagData);

        splice_stream_t *stream = splicestreamCreate(pool, kMuxFrameLength);
        splicestreamPush(stream, wire);

        mux_frame_t frame;
        require(muxPeekCompleteFrame(stream, &frame) == kMuxPeekReady && frame.length == 41 && frame.cid == kTestCid,
                "could not peek splice-backed Mux frame");
        sbuf_t *forward = muxReadFrameBody(stream, &frame, true);
        require(forward == wire && (forward->flags & kSbufFlagSplice) != 0,
                "immediate Mux extraction did not preserve a representable pipe body");
        requireSpliceBody(pool, forward, 41, "immediate splice-backed Mux extraction changed payload bytes");
        splicestreamDestroy(stream);
    }

    {
        sbuf_t *wire = makeSplicePattern(pool, 53);
        muxMakeMuxFrame(wire, kTestCid, kMuxFlagData);

        splice_stream_t *stream = splicestreamCreate(pool, kMuxFrameLength);
        splicestreamPush(stream, wire);

        mux_frame_t frame;
        require(muxPeekCompleteFrame(stream, &frame) == kMuxPeekReady, "could not peek queued splice-backed Mux frame");
        sbuf_t *queued = muxReadFrameBody(stream, &frame, false);
        require((queued->flags & kSbufFlagSplice) == 0, "queued Mux frame extraction retained a private pipe");
        require(sbufGetLength(queued) == 53, "queued splice-backed Mux frame has the wrong payload length");
        for (uint32_t i = 0; i < 53; ++i)
            require(((const uint8_t *) sbufGetRawPtr(queued))[i] == patternByte(i),
                    "queued splice-backed Mux frame changed payload bytes");
        bufferpoolReuseBuffer(pool, queued);
        splicestreamDestroy(stream);
    }
}
#endif

#if WW_HAVE_SPLICE
static void testBatchFallbackEquality(buffer_pool_t *source_pool)
{
    // A destination pool with insufficient splice headroom must select complete
    // ordinary fallback. The source uses a separate real, full-capacity pipe.
    test_pool_t       fallback = testPoolCreateWithSizes(LARGE_BUFFER_SIZE_RAM_LOW, MEDIUM_BUFFER_SIZE_RAM_LOW, 0);
    buffer_pool_fit_t full, tail;
    require(bufferpoolQueryBestFit(fallback.pool, kMuxMaxDataFrameLength, 32, &full) &&
                bufferpoolQueryBestFit(fallback.pool, 1, 32, &tail),
            "batch fallback geometry failed");
    const size_t limit = full.allocation_charge + tail.allocation_charge;
    for (unsigned refuse = 0; refuse < 2; ++refuse)
    {
        mux_parent_output_t output = {0};
        bufferqueueInitEmpty(&output.pending);
        const bool accepted = muxEncodeSpliceBatch(fallback.pool,
                                                   makeLargeSplicePattern(source_pool, kMuxMaxDataFrameLength + 1U),
                                                   kTestCid,
                                                   true,
                                                   &output,
                                                   limit - refuse);
        require(accepted == (refuse == 0), "ordinary fallback batch equality/refusal boundary changed");
        require(output.charge == (refuse ? 0 : limit), "batch fallback charged a prediction instead of actual output");
        c_foreach(entry, ww_sbuffer_queue_t, output.pending.q)
            require(! sbufIsSplice(*entry.ref), "insufficient onward headroom retained a destination pipe");
        muxParentOutputDestroy(&output, fallback.pool);
        require(output.charge == 0, "fallback batch cleanup leaked charge");
    }
    testPoolDestroy(&fallback);
}

static void testBatchWithRetainedIncoming(buffer_pool_t *pool)
{
    splice_stream_t *incoming = splicestreamCreate(pool, 0);
    for (unsigned i = 0; i < 80; ++i)
        require(splicestreamPush(incoming, makeSplicePattern(pool, 1)), "incoming fixture refused");
    const size_t        before = splicestreamCharge(incoming);
    mux_parent_output_t output = {0};
    bufferqueueInitEmpty(&output.pending);
    require(muxEncodeSpliceBatch(
                pool, makeLargeSplicePattern(pool, kMuxMaxDataFrameLength + 1U), kTestCid, true, &output, SIZE_MAX),
            "incoming retention blocked independent output batch");
    require(splicestreamCharge(incoming) == before, "output batch changed incoming ownership");
    while (bufferqueueGetBufCount(&output.pending) != 0)
        bufferpoolReuseBuffer(pool, muxParentOutputPop(&output));
    require(output.charge == 0, "batch drain retained charge");
    muxParentOutputDestroy(&output, pool);
    splicestreamDestroy(incoming);
}
#endif

static void requireEncodedLength(uint32_t payload_length, bool prepend_open, uint32_t expected)
{
    uint32_t actual = 0;
    require(muxTryComputeEncodedLength(payload_length, prepend_open, &actual), "encoded length was rejected");
    require(actual == expected, "encoded length is wrong");
}

static void testEncodedLengthBoundaries(void)
{
    requireEncodedLength(0, false, kMuxFrameLength);
    requireEncodedLength(0, true, 2U * kMuxFrameLength);
    requireEncodedLength(kMuxMaxDataFrameLength - 1U, false, kMuxMaxDataFrameLength - 1U + kMuxFrameLength);
    requireEncodedLength(kMuxMaxDataFrameLength, false, kMuxMaxDataFrameLength + kMuxFrameLength);
    requireEncodedLength(kMuxMaxDataFrameLength + 1U, false, kMuxMaxDataFrameLength + 1U + 2U * kMuxFrameLength);
    requireEncodedLength(2U * kMuxMaxDataFrameLength, false, 2U * kMuxMaxDataFrameLength + 2U * kMuxFrameLength);
    requireEncodedLength(
        2U * kMuxMaxDataFrameLength + 1U, true, 2U * kMuxMaxDataFrameLength + 1U + 4U * kMuxFrameLength);

    requireEncodedLength(UINT32_MAX - 32768U, false, UINT32_MAX);
    requireEncodedLength(UINT32_MAX - 32776U, true, UINT32_MAX);
    uint32_t unchanged = 0xA5A5A5A5U;
    require(! muxTryComputeEncodedLength(UINT32_MAX - 64U, false, &unchanged),
            "near-UINT32_MAX encoded length did not fail");
    require(unchanged == 0xA5A5A5A5U, "failed encoded-length check modified the destination");
    require(! muxTryComputeEncodedLength(UINT32_MAX, true, &unchanged), "UINT32_MAX encoded length did not fail");
}

static void testQueuedSbufCharge(buffer_pool_t *pool)
{
    sbuf_t *empty_small = bufferpoolGetSmallBuffer(pool);
    sbuf_t *one_small   = bufferpoolGetSmallBuffer(pool);
    sbufSetLength(one_small, 1);

    const size_t empty_charge = sbufGetAllocationCharge(empty_small);
    const size_t one_charge   = sbufGetAllocationCharge(one_small);
    require(empty_charge > 0, "an empty queued sbuf has no retained allocation charge");
    require(empty_charge == one_charge, "payload length changed an otherwise identical sbuf allocation charge");
    require(empty_charge ==
                sizeof(sbuf_t) + (size_t) sbufGetTotalCapacity(empty_small) + (size_t) kSbufAllocationAlignment,
            "small-buffer charge omitted real allocation bytes");

    sbuf_t *large = bufferpoolGetLargeBuffer(pool);
    require(sbufGetAllocationCharge(large) ==
                sizeof(sbuf_t) + (size_t) sbufGetTotalCapacity(large) + (size_t) kSbufAllocationAlignment,
            "large-buffer charge omitted real allocation bytes");
    require(sbufGetAllocationCharge(large) != empty_charge, "queued sbuf charge used one fixed pool-tier constant");

    sbuf_t *unpadded = sbufCreateWithPadding(77, 0);
    sbuf_t *padded   = sbufCreateWithPadding(77, 33);
    require(sbufGetAllocationCharge(unpadded) ==
                sizeof(sbuf_t) + (size_t) sbufGetTotalCapacity(unpadded) + (size_t) kSbufAllocationAlignment,
            "dedicated-buffer charge omitted real allocation bytes");
    require(sbufGetAllocationCharge(padded) ==
                sizeof(sbuf_t) + (size_t) sbufGetTotalCapacity(padded) + (size_t) kSbufAllocationAlignment,
            "padded-buffer charge omitted real allocation bytes");
    require(sbufGetAllocationCharge(padded) > sbufGetAllocationCharge(unpadded),
            "queued sbuf charge excluded retained left padding");

    require(! muxQueueChargeWouldReachLimit(10, 9, 20), "below-limit projected charge was rejected");
    require(muxQueueChargeWouldReachLimit(10, 10, 20), "limit equality was not rejected");
    require(muxQueueChargeWouldReachLimit(SIZE_MAX - 4U, 8, SIZE_MAX), "overflowing projected charge was not rejected");
    require(muxQueueChargeWouldReachLimit(0, SIZE_MAX, SIZE_MAX),
            "maximum candidate charge did not reach an equal limit");

    const size_t before = sbufGetAllocationCharge(padded);
    sbufSetLength(padded, 50);
    sbufShiftRight(padded, 17);
    sbufConsume(padded, 10);
    sbufShiftLeft(padded, 8);
    require(sbufGetAllocationCharge(padded) == before, "cursor/length changes reduced allocation charge");
    sbufDestroy(padded);
    sbufDestroy(unpadded);
    bufferpoolReuseBuffer(pool, large);
    bufferpoolReuseBuffer(pool, one_small);
    bufferpoolReuseBuffer(pool, empty_small);
}

static unsigned retention_lifetime_releases;
static void     releaseRetentionLifetime(sbuf_lifetime_t *lifetime)
{
    discard lifetime;
    ++retention_lifetime_releases;
}

static void testEncodeCase(buffer_pool_t *pool, uint32_t payload_length, bool prepend_open, uint32_t data_frames)
{
    sbuf_t         *input       = makePayload(pool, payload_length);
    sbuf_t         *encoded     = NULL;
    sbuf_lifetime_t lifetime    = {.release = releaseRetentionLifetime};
    retention_lifetime_releases = 0;
    sbufAttachLifetime(input, &lifetime);
    mux_encode_result_t result = muxEncodeChildPayload(pool, input, kTestCid, prepend_open, &encoded);
    require(result == kMuxEncodeSuccess && encoded != NULL, "payload encoding failed");

    frame_view_t frames[8];
    uint32_t     count = parseFrames(encoded, frames, ARRAY_SIZE(frames));
    require(count == data_frames + (prepend_open ? 1U : 0U), "payload encoding produced the wrong frame count");
    if (prepend_open)
    {
        require(frames[0].flags == kMuxFlagOpen && frames[0].length == 0, "encoded Open frame is invalid");
        require(frames[0].cid == kTestCid, "encoded Open frame has the wrong cid");
    }
    requirePayload(frames, count, prepend_open ? 1U : 0U, payload_length);
    require(sbufGetLifetime(encoded) == &lifetime && retention_lifetime_releases == 0,
            "encoding released or lost lifetime metadata");
    bufferpoolReuseBuffer(pool, encoded);
    require(retention_lifetime_releases == 1, "encoding did not settle lifetime once");
}

static void testEncodingAndOwnership(buffer_pool_t *pool)
{
    sbuf_t *input   = makePayload(pool, kMuxMaxDataFrameLength);
    sbuf_t *encoded = NULL;
    require(muxEncodeChildPayload(pool, input, kTestCid, false, &encoded) == kMuxEncodeSuccess,
            "in-place encode failed");
    require(encoded == input, "in-place encode did not return its input");
    bufferpoolReuseBuffer(pool, encoded);

    input = bufferpoolGetLargeBuffer(pool);
    sbufSetLength(input, kMuxMaxDataFrameLength + 1U);
    for (uint32_t i = 0; i < sbufGetLength(input); ++i)
        sbufGetMutablePtr(input)[i] = patternByte(i);
    sbuf_t *original_input = input;
    encoded                = NULL;
    require(muxEncodeChildPayload(pool, input, kTestCid, false, &encoded) == kMuxEncodeSuccess,
            "expanded encode failed");
    require(encoded != NULL && encoded != original_input, "expanded encode did not return a new buffer");

    sbuf_t *reacquired = bufferpoolGetLargeBuffer(pool);
    require(reacquired == original_input, "expanded encode did not recycle its input exactly once");
    bufferpoolReuseBuffer(pool, reacquired);
    bufferpoolReuseBuffer(pool, encoded);

    input          = bufferpoolGetLargeBuffer(pool);
    original_input = input;
    input->len     = UINT32_MAX;
    encoded        = (sbuf_t *) (uintptr_t) 1U;
    require(muxEncodeChildPayload(pool, input, kTestCid, true, &encoded) == kMuxEncodeLengthOverflow,
            "unrepresentable encoded length did not fail");
    require(encoded == NULL, "failed encode returned an output buffer");

    reacquired = bufferpoolGetLargeBuffer(pool);
    require(reacquired == original_input, "failed encode did not recycle its input exactly once");
    bufferpoolReuseBuffer(pool, reacquired);

    testEncodeCase(pool, 0, false, 1);
    testEncodeCase(pool, 0, true, 1);
    testEncodeCase(pool, kMuxMaxDataFrameLength - 1U, false, 1);
    testEncodeCase(pool, kMuxMaxDataFrameLength, true, 1);
    testEncodeCase(pool, kMuxMaxDataFrameLength + 1U, false, 2);
    testEncodeCase(pool, 2U * kMuxMaxDataFrameLength, false, 2);
    testEncodeCase(pool, 2U * kMuxMaxDataFrameLength + 1U, true, 3);
}

static void testPausedRetentionStorage(buffer_pool_t *pool)
{
    const uint32_t lengths[] = {0, 1, 4097, kMuxMaxDataFrameLength, bufferpoolGetMediumBufferSize(pool) + 1};
    for (size_t i = 0; i < ARRAY_SIZE(lengths); ++i)
    {
        sbuf_t         *input             = makePayload(pool, lengths[i]);
        const uint32_t  original_capacity = sbufGetTotalCapacityNoPadding(input);
        sbuf_lifetime_t lifetime          = {.release = releaseRetentionLifetime};
        sbufAttachLifetime(input, &lifetime);
        retention_lifetime_releases = 0;
        sbuf_t        *retained     = muxPrepareQueuedPayload(pool, input);
        const uint32_t expected = lengths[i] <= bufferpoolGetSmallBufferSize(pool) ? bufferpoolGetSmallBufferSize(pool)
                                  : lengths[i] <= bufferpoolGetMediumBufferSize(pool)
                                      ? bufferpoolGetMediumBufferSize(pool)
                                      : original_capacity;
        require(sbufGetTotalCapacityNoPadding(retained) == expected, "paused retention selected the wrong pooled tier");
        require(sbufGetLength(retained) == lengths[i], "paused retention changed the payload length");
        require(sbufGetLeftCapacity(retained) >= bufferpoolGetLargeBufferPadding(pool),
                "paused retention lost onward padding");
        for (uint32_t j = 0; j < lengths[i]; ++j)
            require(((const uint8_t *) sbufGetRawPtr(retained))[j] == patternByte(j),
                    "paused retention changed payload bytes");
        require(sbufGetLifetime(retained) == &lifetime && retention_lifetime_releases == 0,
                "paused retention released or lost the payload lifetime");
        require(muxPrepareQueuedPayload(pool, retained) == retained,
                "suitably sized retained storage was copied again");
        bufferpoolReuseBuffer(pool, retained);
        require(retention_lifetime_releases == 1, "paused retention failed to settle the lifetime exactly once");
    }
}

static void testQueuedFrameExtraction(buffer_pool_t *pool)
{
    const uint32_t lengths[] = {
        0, 1, 1024, 4097, bufferpoolGetMediumBufferSize(pool) / 2, 32768, 32769, kMuxMaxDataFrameLength, UINT16_MAX};
    for (size_t i = 0; i < ARRAY_SIZE(lengths); ++i)
        for (unsigned int fragmented = 0; fragmented < 2; ++fragmented)
        {

            splice_stream_t  *stream = splicestreamCreate(pool, kMuxFrameLength);
            const uint32_t    length = lengths[i];
            sbuf_t           *input  = makePayload(pool, length);
            mux_wire_header_t wire;
            muxSetMuxFrameHeader(&wire, (mux_length_t) length, kTestCid, kMuxFlagData);
            sbufShiftLeft(input, kMuxFrameLength);
            memoryCopy(sbufGetMutablePtr(input), &wire, kMuxFrameLength);
            if (fragmented)
            {
                sbuf_t *head = bufferpoolGetSmallBuffer(pool);
                // Split even the empty DATA frame's header across stream chunks.
                sbufSetLength(head, 3);
                memoryCopy(sbufGetMutablePtr(head), sbufGetRawPtr(input), 3);
                sbufShiftRight(input, 3);
                splicestreamPush(stream, head);
            }
            splicestreamPush(stream, input);
            mux_frame_t frame;
            require(muxPeekCompleteFrame(stream, &frame) == kMuxPeekReady && frame.length == length &&
                        frame.cid == kTestCid && splicestreamLength(stream) == length + kMuxFrameLength,
                    "frame peek consumed bytes or decoded the wrong header");
            sbuf_t *read = muxReadFrameBody(stream, &frame, false);
            require(sbufGetLength(read) == length && (splicestreamLength(stream) == 0),
                    "queued frame extraction changed wire length");
            require(sbufGetLeftCapacity(read) >= bufferpoolGetLargeBufferPadding(pool),
                    "queued frame extraction consumed onward padding");
            buffer_pool_fit_t fit;
            require(bufferpoolQueryBestFit(pool, length, bufferpoolGetLargeBufferPadding(pool), &fit),
                    "invalid test geometry");
            const uint32_t expected = fit.payload_capacity;
            require(sbufGetTotalCapacityNoPadding(read) == expected,
                    "queued frame did not select final pooled storage");
            for (uint32_t j = 0; j < length; ++j)
                require(((const uint8_t *) sbufGetRawPtr(read))[j] == patternByte(j),
                        "queued frame changed payload bytes");
            bufferpoolReuseBuffer(pool, read);
            splicestreamDestroy(stream);
        }

    splice_stream_t  *stream = splicestreamCreate(pool, kMuxFrameLength);
    sbuf_t           *input  = bufferpoolGetMediumBuffer(pool);
    mux_frame_t       frame;
    mux_wire_header_t wire;
    muxSetMuxFrameHeader(&wire, 4097, kTestCid, kMuxFlagData);
    sbufSetLength(input, 4097 + kMuxFrameLength);
    memoryCopy(sbufGetMutablePtr(input), &wire, kMuxFrameLength);
    splicestreamPush(stream, input);
    require(muxPeekCompleteFrame(stream, &frame) == kMuxPeekReady, "could not peek an already suitable whole frame");
    sbuf_t *read = muxReadFrameBody(stream, &frame, false);
    require(sbufGetLength(read) == 4097, "queued whole medium frame has wrong length");
    bufferpoolReuseBuffer(pool, read);
    splicestreamDestroy(stream);
}

static void testQueueCapacityCharge(buffer_pool_t *pool)
{
    sbuf_t *ordinary = makePayload(pool, 3);
    require(sbufGetQueueCharge(ordinary) == sbufGetAllocationCharge(ordinary), "ordinary allocation charge changed");
    bufferpoolReuseBuffer(pool, ordinary);
    size_t     charge        = 123;
    const bool representable = sbufTryComputeQueueCharge(UINT32_MAX, &charge);
    require(representable == (SIZE_MAX > UINT32_MAX), "queue charge overflow was not checked on this word size");
    if (! representable)
        require(charge == 123, "refused charge changed output");
    splice_stream_t *stream = splicestreamCreate(pool, 0);
    require(splicestreamPush(stream, makePayload(pool, 1)), "arithmetic stream setup failed");
    charge = 123;
    require(! muxTryParentReceiveCharge(SIZE_MAX, stream, &charge) && charge == 123 &&
                muxParentReceiveOverLimit(SIZE_MAX, stream, 0),
            "combined charge overflow wrapped under unlimited policy");
    splicestreamDestroy(stream);
#if WW_HAVE_SPLICE
    sbuf_t    *small    = makeSplicePattern(pool, 32);
    sbuf_t    *large    = makeSplicePattern(pool, 32);
    const long page     = sysconf(_SC_PAGESIZE);
    int        capacity = fcntl(sbufSpliceMetadata(small).pipefd[0], F_SETPIPE_SZ, (int) page);
    require(capacity > 0, "cannot shrink test pipe");
    require(sbufGetQueueCharge(small) == sbufGetQueueCharge(large), "kernel capacity affected queue charge");
    require(sbufGetQueueCharge(small) == sizeof(sbuf_t) + small->capacity + kSbufAllocationAlignment,
            "splice queue charge omitted logical capacity or counted kernel/control storage");
    require(sbufGetAllocationCharge(small) ==
                sizeof(sbuf_t) + small->l_pad + SPLICE_BUFFER_STORAGE_SIZE + kSbufAllocationAlignment,
            "physical splice allocation helper changed");
    bufferpoolReuseBuffer(pool, small);
    bufferpoolReuseBuffer(pool, large);
    for (unsigned prefix = 0; prefix <= 3; ++prefix)
    {
        sbuf_t *empty   = sbufCreateSplice(64);
        empty->capacity = empty->l_pad;
        sbufShiftLeft(empty, prefix);
        require(sbufGetQueueCharge(empty) == sizeof(sbuf_t) + 64 + kSbufAllocationAlignment,
                "empty/prefix-only charge counted padding twice");
        sbufDestroy(empty);
    }
#endif
}

#include "mux_candidate_preparation_cases.h"

static void testRetainedOutputAccounting(buffer_pool_t *pool)
{
    mux_parent_output_t output = {0};
    bufferqueueInitEmpty(&output.pending);
    sbuf_t      *first        = makePayload(pool, 1);
    const size_t first_charge = sbufGetQueueCharge(first);
    require(muxParentOutputEnqueue(&output, &first, first_charge), "parent ordinary equality refused");
#if WW_HAVE_SPLICE
    sbuf_t      *pipe     = makeSplicePattern(pool, 32);
    sbuf_t      *original = pipe;
    const size_t charge   = sbufGetQueueCharge(pipe);
    require(! muxParentOutputEnqueue(&output, &pipe, first_charge + charge - 1) && pipe == original &&
                output.charge == first_charge,
            "refusal changed ownership or charge");
    require(muxParentOutputEnqueue(&output, &pipe, first_charge + charge) && pipe == original,
            "pipe equality admission replaced body");
#endif
    sbuf_t *entry = muxParentOutputPop(&output);
    require(sbufGetLength(entry) == 1, "output FIFO reordered entries");
    bufferpoolReuseBuffer(pool, entry);
#if WW_HAVE_SPLICE
    require(output.charge == charge, "ordinary pop changed retained splice queue charge");
    entry = muxParentOutputPop(&output);
    require(entry == original && output.charge == 0, "pipe pop did not settle before transfer");
    requireSpliceBody(pool, entry, 32, "output retention corrupted pipe");
#endif
    entry = makePayload(pool, 0);
    require(muxParentOutputEnqueue(&output, &entry, SIZE_MAX), "empty output refused");
    muxParentOutputDestroy(&output, pool);
    require(output.charge == 0, "output destruction retained charge");
}

static void testHeaderPeekBoundaries(buffer_pool_t *pool)
{
    const uint32_t lengths[] = {0,
                                1,
                                65527,
                                65535,
                                65536,
                                kMuxMaxDataFrameLength - 1,
                                kMuxMaxDataFrameLength,
                                kMuxMaxDataFrameLength + 1,
                                0xffffff};
    for (size_t i = 0; i < ARRAY_SIZE(lengths); ++i)
        for (uint32_t split = 1; split < kMuxFrameLength; ++split)
        {
            uint32_t         length = lengths[i];
            const uint8_t    wire[] = {(uint8_t) (length >> 16),
                                       (uint8_t) (length >> 8),
                                       (uint8_t) length,
                                       kMuxFlagData,
                                       0x12,
                                       0x34,
                                       0x56,
                                       0x78};
            splice_stream_t *stream = splicestreamCreate(pool, kMuxFrameLength);
            pushBytes(pool, stream, wire, split);
            mux_frame_t frame;
            require(muxPeekCompleteFrame(stream, &frame) == kMuxPeekNeedMore, "partial header was decoded");
            pushBytes(pool, stream, wire + split, kMuxFrameLength - split);
            const mux_peek_result_t expected = length > kMuxMaxDataFrameLength ? kMuxPeekInvalidLength
                                               : length == 0                   ? kMuxPeekReady
                                                                               : kMuxPeekNeedMore;
            for (unsigned peek = 0; peek < 4; ++peek)
                require(muxPeekCompleteFrame(stream, &frame) == expected && frame.length == length &&
                            frame.cid == kTestCid && splicestreamLength(stream) == kMuxFrameLength,
                        "repeated peek truncated length, consumed bytes, or waited for forbidden body");
            splicestreamDestroy(stream);
        }
}

#if WW_HAVE_SPLICE
static void testMaximumSpliceWrapper(buffer_pool_t *pool)
{
    if (! testPipeCapacity(pool, kMuxMaxDataFrameLength, "maximum fitting Mux splice wrapper"))
        return;
    const uint32_t lengths[] = {65536, kMuxMaxDataFrameLength};
    for (size_t i = 0; i < ARRAY_SIZE(lengths); ++i)
        for (unsigned open = 0; open < 2; ++open)
        {
            sbuf_t   *input   = makeLargeSplicePattern(pool, lengths[i]);
            const int fd      = sbufSpliceMetadata(input).pipefd[0];
            sbuf_t   *encoded = NULL;
            require(muxEncodeChildPayload(pool, input, kTestCid, open != 0, &encoded) == kMuxEncodeSuccess &&
                        encoded == input && sbufSpliceMetadata(encoded).pipefd[0] == fd,
                    "fitting maximum splice input replaced original wrapper or pipe");
            mux_frame_t frame;
            muxDecodeFrameHeader((const uint8_t *) sbufGetRawPtr(encoded) + (open ? kMuxFrameLength : 0), &frame);
            require(frame.length == lengths[i] && frame.flags == kMuxFlagData, "fitting splice was split");
            sbufShiftRight(encoded, (open ? 2U : 1U) * kMuxFrameLength);
            requireSpliceBody(pool, encoded, lengths[i], "maximum fitting splice body changed");
        }
}

/* Removing the first header leaves a partial source page. Even a 1 MiB
 * destination runs out of pipe slots before all 1 MiB body bytes fit. */
static void testMaximumMixedFrame(buffer_pool_t *pool, bool mixed)
{
    test_pool_t sources = testPoolCreateWithSizes(LARGE_BUFFER_SIZE_RAM_LOW, MEDIUM_BUFFER_SIZE_RAM_LOW, 32);
    if (! testPipeCapacity(sources.pool, 65536, "maximum Mux frame across 64 KiB pipes"))
    {
        testPoolDestroy(&sources);
        return;
    }
    const uint32_t length   = kMuxMaxDataFrameLength;
    uint8_t       *wire     = memoryAllocate(length + kMuxFrameLength + 3U);
    const uint8_t  header[] = {0x10, 0, 0, kMuxFlagData, 0x12, 0x34, 0x56, 0x78};
    memoryCopy(wire, header, sizeof(header));
    for (uint32_t i = 0; i < length; ++i)
        wire[kMuxFrameLength + i] = patternByte(i);
    memoryCopy(wire + kMuxFrameLength + length, header, 3);

    splice_stream_t *stream = splicestreamCreate(pool, kMuxFrameLength);
    for (uint32_t offset = 0, chunk = 0; offset < length + kMuxFrameLength + 3U; ++chunk)
    {
        const uint32_t count = min(65536U, length + kMuxFrameLength + 3U - offset);
        if (mixed && chunk % 3U == 1)
            pushBytes(pool, stream, wire + offset, count);
        else
        {
            const uint32_t prefix = mixed && chunk != 0 ? min(5U, count) : 0;
            sbuf_t        *input  = bufferpoolGetSpliceBuffer(sources.pool);
            require(input != NULL, "cannot allocate mixed-frame source");
            uint32_t written = prefix;
            while (written < count)
            {
                ssize_t n = write(sbufSpliceMetadata(input).pipefd[1], wire + offset + written, count - written);
                if (n < 0 && errno == EINTR)
                    continue;
                require(n > 0, "real mixed-frame source write failed");
                written += (uint32_t) n;
            }
            input->capacity = input->l_pad + count - prefix;
            sbufSetLength(input, count - prefix);
            sbufShiftLeft(input, prefix);
            memoryCopy(sbufGetMutablePtr(input), wire + offset, prefix);
            require(splicestreamPush(stream, input), "mixed-frame stream push failed");
        }
        offset += count;
    }
    mux_frame_t frame;
    require(muxPeekCompleteFrame(stream, &frame) == kMuxPeekReady && frame.length == length,
            "maximum mixed frame not ready");
    sbuf_t *body = muxReadFrameBody(stream, &frame, true);
    require((body->flags & kSbufFlagSplice) == 0 && sbufGetLength(body) == length &&
                sbufGetLeftCapacity(body) >= bufferpoolGetLargeBufferPadding(pool),
            "maximum slot-pressure fallback lost ordinary storage, length or padding");
    for (uint32_t i = 0; i < length; ++i)
        require(sbufGetMutablePtr(body)[i] == patternByte(i), "maximum mixed-frame fallback corrupted bytes");
    require(splicestreamLength(stream) == 3 && muxPeekCompleteFrame(stream, &frame) == kMuxPeekNeedMore,
            "maximum mixed extraction consumed the next partial header");
    bufferpoolReuseBuffer(pool, body);
    splicestreamDestroy(stream);
    memoryFree(wire);
    testPoolDestroy(&sources);
}
#endif

int main(void)
{
    test_pool_t test_pool = testPoolCreateWithSizes(kTestLargeBufferSize, MEDIUM_BUFFER_SIZE_RAM_HIGH, 32);

    testQueueCapacityCharge(test_pool.pool);
    testRetainedCandidatePreparation(test_pool.pool);
    testRetainedOutputAccounting(test_pool.pool);
    testPausedRetentionStorage(test_pool.pool);
    testQueuedFrameExtraction(test_pool.pool);
    testEveryHeaderFlag();
    testControlAndClientSequences(test_pool.pool);
    testCompleteFrameParsing(test_pool.pool);
#if WW_HAVE_SPLICE
    testMaximumSpliceWrapper(test_pool.pool);
    testMaximumMixedFrame(test_pool.pool, false);
    testMaximumMixedFrame(test_pool.pool, true);
    testSpliceMuxPaths(test_pool.pool);
    if (testPipeCapacity(test_pool.pool, kMuxMaxDataFrameLength, "Mux batch with independent incoming retention"))
    {
        testBatchWithRetainedIncoming(test_pool.pool);
        testBatchFallbackEquality(test_pool.pool);
    }
#endif
    testHeaderPeekBoundaries(test_pool.pool);
    testEncodedLengthBoundaries();
    testQueuedSbufCharge(test_pool.pool);
    testEncodingAndOwnership(test_pool.pool);

    testPoolDestroy(&test_pool);
    test_pool = testPoolCreateWithSizes(LARGE_BUFFER_SIZE_RAM_LOW, MEDIUM_BUFFER_SIZE_RAM_LOW, 32);
#if WW_HAVE_SPLICE
    testMaximumMixedFrame(test_pool.pool, false);
    testMaximumMixedFrame(test_pool.pool, true);
#endif
    testPausedRetentionStorage(test_pool.pool);
    testQueuedFrameExtraction(test_pool.pool);
    testPoolDestroy(&test_pool);
    puts("muxcommon_wire_test: all cases passed");
    return 0;
}
