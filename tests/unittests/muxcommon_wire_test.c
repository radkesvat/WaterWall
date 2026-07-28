#include "MuxCommon/mux_wire.h"

#include <stdio.h>
#include <stdlib.h>

enum
{
    kTestCid             = 0x12345678U,
    kTestLargeBufferSize = 4U * kMuxMaxDataFrameLength,
    kTestPoolCapacity    = 16
};

typedef struct test_pool_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
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

static test_pool_t testPoolCreate(void)
{
    test_pool_t result = {
        .large_master = masterpoolCreateWithCapacity(kTestPoolCapacity),
        .small_master = masterpoolCreateWithCapacity(kTestPoolCapacity),
        .pool         = NULL,
    };
    require(result.large_master != NULL && result.small_master != NULL, "failed to create master pools");

    result.pool =
        bufferpoolCreate(result.large_master, result.small_master, kTestPoolCapacity, kTestLargeBufferSize, 1024);
    require(result.pool != NULL, "failed to create buffer pool");
    bufferpoolUpdateAllocationPaddings(result.pool, kMuxFrameLength * 2U, kMuxFrameLength * 2U);
    return result;
}

static void testPoolDestroy(test_pool_t *test_pool)
{
    bufferpoolDestroy(test_pool->pool);
    masterpoolMakeEmpty(test_pool->large_master);
    masterpoolMakeEmpty(test_pool->small_master);
    masterpoolDestroy(test_pool->large_master);
    masterpoolDestroy(test_pool->small_master);
}

static uint8_t patternByte(uint32_t index)
{
    return (uint8_t) ((index * 31U + 17U) & 0xFFU);
}

static sbuf_t *makePayload(buffer_pool_t *pool, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetLargeBuffer(pool);
    require(length <= sbufGetMaximumWriteableSize(buf), "test payload exceeds the large test buffer");
    sbufSetLength(buf, length);

    uint8_t *bytes = sbufGetMutablePtr(buf);
    for (uint32_t i = 0; i < length; ++i)
    {
        bytes[i] = patternByte(i);
    }
    return buf;
}

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
        memoryCopy(&frame, bytes + offset, kMuxFrameLength);
        offset += kMuxFrameLength;

        const uint32_t payload_length = be16toh(frame.length);
        require(length - offset >= payload_length, "encoded data ends inside a payload");

        frames[count++] = (frame_view_t) {
            .flags = frame.flags, .cid = be32toh(frame.cid), .length = payload_length, .data = bytes + offset};
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
    static const uint8_t flags[] = {kMuxFlagOpen, kMuxFlagClose, kMuxFlagFlowPause, kMuxFlagFlowResume, kMuxFlagData};

    for (size_t i = 0; i < ARRAY_SIZE(flags); ++i)
    {
        mux_frame_t frame;
        muxSetMuxFrameHeader(&frame, 0x4567U, kTestCid, flags[i]);

        require(be16toh(frame.length) == 0x4567U, "header length byte order failed");
        require(frame.flags == flags[i], "header flag failed");
        require(frame._pad1 == 0, "header reserved byte is not zero");
        require(be32toh(frame.cid) == kTestCid, "header cid byte order failed");
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

static void pushBytes(buffer_pool_t *pool, buffer_stream_t *stream, const uint8_t *bytes, uint32_t length)
{
    sbuf_t *chunk = bufferpoolGetLargeBuffer(pool);
    sbufSetLength(chunk, length);
    memoryCopy(sbufGetMutablePtr(chunk), bytes, length);
    bufferstreamPush(stream, chunk);
}

static void testCompleteFrameParsing(buffer_pool_t *pool)
{
    const uint8_t payload[] = {0x10, 0x20, 0x30, 0x40};
    uint8_t       wire[kMuxFrameLength + ARRAY_SIZE(payload)];
    mux_frame_t   wire_header;
    muxSetMuxFrameHeader(&wire_header, ARRAY_SIZE(payload), kTestCid, kMuxFlagData);
    memoryCopy(wire, &wire_header, kMuxFrameLength);
    memoryCopy(wire + kMuxFrameLength, payload, ARRAY_SIZE(payload));

    buffer_stream_t stream = bufferstreamCreate(pool, kMuxFrameLength);
    mux_frame_t     decoded;

    pushBytes(pool, &stream, wire, kMuxFrameLength - 1U);
    require(muxReadCompleteFrame(&stream, &decoded) == NULL, "an incomplete header was consumed");
    require(bufferstreamGetBufLen(&stream) == kMuxFrameLength - 1U, "incomplete header changed stream length");

    pushBytes(pool, &stream, wire + kMuxFrameLength - 1U, 3U);
    require(muxReadCompleteFrame(&stream, &decoded) == NULL, "an incomplete payload was consumed");
    require(bufferstreamGetBufLen(&stream) == kMuxFrameLength + 2U, "incomplete payload changed stream length");

    pushBytes(pool, &stream, wire + kMuxFrameLength + 2U, 2U);
    sbuf_t *complete = muxReadCompleteFrame(&stream, &decoded);
    require(complete != NULL, "a complete fragmented frame was not returned");
    require(bufferstreamGetBufLen(&stream) == 0, "complete frame was not consumed exactly");
    require(decoded.length == ARRAY_SIZE(payload), "decoded frame length is wrong");
    require(decoded.flags == kMuxFlagData, "decoded frame flag is wrong");
    require(decoded.cid == kTestCid, "decoded frame cid is wrong");
    require(sbufGetLength(complete) == sizeof(wire), "returned wire frame has the wrong length");
    bufferpoolReuseBuffer(pool, complete);
    bufferstreamDestroy(&stream);

    stream = bufferstreamCreate(pool, kMuxFrameLength);
    muxSetMuxFrameHeader(&wire_header, 0, kTestCid, kMuxFlagFlowPause);
    pushBytes(pool, &stream, (const uint8_t *) &wire_header, kMuxFrameLength);
    complete = muxReadCompleteFrame(&stream, &decoded);
    require(complete != NULL, "an exact zero-length frame was not returned");
    require(decoded.length == 0 && decoded.flags == kMuxFlagFlowPause, "zero-length frame decoded incorrectly");
    bufferpoolReuseBuffer(pool, complete);
    bufferstreamDestroy(&stream);
}

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

    uint32_t unchanged = 0xA5A5A5A5U;
    require(! muxTryComputeEncodedLength(UINT32_MAX - 64U, false, &unchanged),
            "near-UINT32_MAX encoded length did not fail");
    require(unchanged == 0xA5A5A5A5U, "failed encoded-length check modified the destination");
    require(! muxTryComputeEncodedLength(UINT32_MAX, true, &unchanged), "UINT32_MAX encoded length did not fail");
    require(! muxTryComputeEncodedLength(1, false, NULL), "NULL encoded-length destination was accepted");
}

static void testEncodeCase(buffer_pool_t *pool, uint32_t payload_length, bool prepend_open, uint32_t data_frames)
{
    sbuf_t             *input   = makePayload(pool, payload_length);
    sbuf_t             *encoded = NULL;
    mux_encode_result_t result  = muxEncodeChildPayload(pool, input, kTestCid, prepend_open, &encoded);
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
    bufferpoolReuseBuffer(pool, encoded);
}

static void testEncodingAndOwnership(buffer_pool_t *pool)
{
    sbuf_t *input   = makePayload(pool, kMuxMaxDataFrameLength);
    sbuf_t *encoded = NULL;
    require(muxEncodeChildPayload(pool, input, kTestCid, false, &encoded) == kMuxEncodeSuccess,
            "in-place encode failed");
    require(encoded == input, "in-place encode did not return its input");
    bufferpoolReuseBuffer(pool, encoded);

    input                  = makePayload(pool, kMuxMaxDataFrameLength + 1U);
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

    testEncodeCase(pool, kMuxMaxDataFrameLength - 1U, false, 1);
    testEncodeCase(pool, kMuxMaxDataFrameLength, true, 1);
    testEncodeCase(pool, kMuxMaxDataFrameLength + 1U, false, 2);
    testEncodeCase(pool, 2U * kMuxMaxDataFrameLength, false, 2);
    testEncodeCase(pool, 2U * kMuxMaxDataFrameLength + 1U, true, 3);
}

int main(void)
{
    test_pool_t test_pool = testPoolCreate();

    testEveryHeaderFlag();
    testControlAndClientSequences(test_pool.pool);
    testCompleteFrameParsing(test_pool.pool);
    testEncodedLengthBoundaries();
    testEncodingAndOwnership(test_pool.pool);

    testPoolDestroy(&test_pool);
    puts("muxcommon_wire_test: all cases passed");
    return 0;
}
