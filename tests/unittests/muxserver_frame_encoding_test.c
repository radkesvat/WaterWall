/*
 * MuxServer payload framing.
 *
 * Mirror of the MuxClient framing test, minus the Open frame: MuxServer never opens a child, it only answers one.
 * An oversized but valid child payload is fragmented into consecutive DATA frames, and a downstream batch of
 * complete frames is drained instead of being judged an overflow.
 */
#include "MuxServer/structure.h"

#include "tunnel_line_failure_harness.h"

enum
{
    kTestLargeBufferSize = 2u * 1024u * 1024u,
    kTestChildCid        = 11,
    kTestMaxFrames       = 64
};

// ---------------------------------------------------------------------------
// wire helpers
// ---------------------------------------------------------------------------

typedef struct frame_view_s
{
    uint8_t        flags;
    uint32_t       cid;
    uint32_t       length;
    const uint8_t *data;
} frame_view_t;

static uint32_t parseFrames(const uint8_t *bytes, uint32_t len, frame_view_t *out, uint32_t max_frames)
{
    uint32_t offset = 0;
    uint32_t count  = 0;

    while (offset < len)
    {
        twfRequire(len - offset >= kMuxFrameLength, "the encoded stream ends inside a frame header");
        twfRequire(count < max_frames, "the encoded stream has more frames than the test can hold");

        const uint32_t length = ((uint32_t) bytes[offset] << 8U) | (uint32_t) bytes[offset + 1U];
        const uint8_t  flags  = bytes[offset + 2U];
        const uint32_t cid    = ((uint32_t) bytes[offset + 4U] << 24U) | ((uint32_t) bytes[offset + 5U] << 16U) |
                             ((uint32_t) bytes[offset + 6U] << 8U) | (uint32_t) bytes[offset + 7U];

        offset += kMuxFrameLength;
        twfRequire(len - offset >= length, "the encoded stream ends inside a frame body");

        out[count++] = (frame_view_t) {.flags = flags, .cid = cid, .length = length, .data = bytes + offset};
        offset += length;
    }

    return count;
}

static void writeFrameHeader(uint8_t *out, uint32_t length, uint8_t flags, uint32_t cid)
{
    out[0] = (uint8_t) ((length >> 8U) & 0xFFU);
    out[1] = (uint8_t) (length & 0xFFU);
    out[2] = flags;
    out[3] = 0;
    out[4] = (uint8_t) ((cid >> 24U) & 0xFFU);
    out[5] = (uint8_t) ((cid >> 16U) & 0xFFU);
    out[6] = (uint8_t) ((cid >> 8U) & 0xFFU);
    out[7] = (uint8_t) (cid & 0xFFU);
}

static uint8_t patternByte(uint32_t index)
{
    return (uint8_t) ((index * 31U + 17U) & 0xFFU);
}

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------

typedef struct muxserver_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *mux;
    tunnel_t        *next;
    line_t          *parent_l;
    line_t          *child_l;
    uint8_t         *capture;
} muxserver_fixture_t;

static void fixtureSetup(muxserver_fixture_t *fixture, uint32_t capture_capacity)
{
    memoryZero(&fixture->trace, sizeof(fixture->trace));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, kMuxFrameLength * 2);

    fixture->capture = memoryAllocate(capture_capacity);
    twfRequire(fixture->capture != NULL, "failed to allocate the neighbour capture buffer");
    fixture->trace.capture          = fixture->capture;
    fixture->trace.capture_capacity = capture_capacity;

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->mux  = tunnelCreate(NULL, sizeof(muxserver_tstate_t), sizeof(muxserver_lstate_t));
    twfRequire(fixture->mux != NULL, "failed to create the MuxServer tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);

    tunnelBind(fixture->prev, fixture->mux);
    tunnelBind(fixture->mux, fixture->next);

    muxserver_tstate_t *ts           = tunnelGetState(fixture->mux);
    ts->child_buffer_limit           = kMuxDefaultChildBufferLimit;
    ts->child_buffer_pause_tolerance = kMuxDefaultChildBufferPauseTolerance;
    ts->parent_buffer_limit          = kMuxDefaultParentBufferLimit;

    fixture->parent_l = twfLineCreate(fixture->mux->lstate_size);
    fixture->child_l  = twfLineCreate(fixture->mux->lstate_size);

    muxserver_lstate_t *parent_ls = lineGetState(fixture->parent_l, fixture->mux);
    muxserver_lstate_t *child_ls  = lineGetState(fixture->child_l, fixture->mux);

    muxserverLinestateInitialize(parent_ls, fixture->parent_l, false, 0);
    muxserverLinestateInitialize(child_ls, fixture->child_l, true, kTestChildCid);
    muxserverJoinConnection(parent_ls, child_ls);
}

static void fixtureTeardown(muxserver_fixture_t *fixture)
{
    muxserver_lstate_t *parent_ls = lineGetState(fixture->parent_l, fixture->mux);
    muxserver_lstate_t *child_ls  = lineGetState(fixture->child_l, fixture->mux);

    muxserverLeaveConnection(child_ls);
    muxserverLinestateDestroy(child_ls);
    muxserverLinestateDestroy(parent_ls);

    twfRequireNoLeakedBuffers();

    twfLineDestroy(fixture->child_l);
    twfLineDestroy(fixture->parent_l);
    memoryFree(fixture->capture);
    memoryFree(fixture->prev);
    memoryFree(fixture->mux);
    memoryFree(fixture->next);
}

static sbuf_t *makePatternPayload(muxserver_fixture_t *fixture, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetLargeBuffer(fixture->env.pool);
    buf         = sbufReserveSpace(buf, length);
    sbufSetLength(buf, length);

    uint8_t *raw = sbufGetMutablePtr(buf);
    for (uint32_t i = 0; i < length; ++i)
    {
        raw[i] = patternByte(i);
    }
    return buf;
}

static void requireReassembledPattern(const frame_view_t *frames, uint32_t frame_count, uint32_t expected_length)
{
    uint32_t consumed = 0;
    for (uint32_t i = 0; i < frame_count; ++i)
    {
        twfRequireEqualU32(frames[i].flags, kMuxFlagData, "a fragment carries a flag other than Data");
        twfRequireEqualU32(frames[i].cid, kTestChildCid, "a fragment carries the wrong connection id");
        twfRequire(frames[i].length <= kMuxMaxDataFrameLength, "a fragment exceeds the per-frame limit");

        for (uint32_t b = 0; b < frames[i].length; ++b)
        {
            twfRequire(frames[i].data[b] == patternByte(consumed + b), "the reassembled payload does not match");
        }
        consumed += frames[i].length;
    }

    twfRequireEqualU32(consumed, expected_length, "the reassembled payload has the wrong length");
}

// ---------------------------------------------------------------------------
// cases
// ---------------------------------------------------------------------------

static void caseDownstreamFraming(uint32_t payload_length, uint32_t expected_frames, const char *case_name)
{
    twfSetCase(case_name);

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture, payload_length + (kTestMaxFrames * kMuxFrameLength));

    muxserverTunnelDownStreamPayload(fixture.mux, fixture.child_l, makePatternPayload(&fixture, payload_length));

    frame_view_t frames[kTestMaxFrames];
    uint32_t     frame_count = parseFrames(fixture.capture, fixture.trace.capture_len, frames, kTestMaxFrames);

    twfRequireEqualU32(frame_count, expected_frames, "the payload produced the wrong frame count");
    requireReassembledPattern(frames, frame_count, payload_length);

    // A second payload must produce the same framing; MuxServer never emits an Open frame.
    fixture.trace.capture_len = 0;
    muxserverTunnelDownStreamPayload(fixture.mux, fixture.child_l, makePatternPayload(&fixture, payload_length));

    frame_count = parseFrames(fixture.capture, fixture.trace.capture_len, frames, kTestMaxFrames);
    twfRequireEqualU32(frame_count, expected_frames, "the second payload produced the wrong frame count");
    for (uint32_t i = 0; i < frame_count; ++i)
    {
        twfRequire(frames[i].flags != kMuxFlagOpen, "MuxServer emitted an Open frame");
    }
    requireReassembledPattern(frames, frame_count, payload_length);

    fixtureTeardown(&fixture);
}

static void caseLargeCompleteBatchIsDrained(void)
{
    twfSetCase("a batch above the read-stream limit is drained as complete frames");

    enum
    {
        kBatchFrames      = 20,
        kBatchFrameLength = 60000
    };

    const uint32_t batch_bytes = kBatchFrames * (kBatchFrameLength + kMuxFrameLength);
    twfRequire(batch_bytes > kMaxMainChannelBufferSize, "the batch must exceed the read-stream limit to be a test");

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture, batch_bytes);

    sbuf_t *batch = bufferpoolGetLargeBuffer(fixture.env.pool);
    batch         = sbufReserveSpace(batch, batch_bytes);
    sbufSetLength(batch, batch_bytes);

    uint8_t *raw      = sbufGetMutablePtr(batch);
    uint32_t offset   = 0;
    uint32_t produced = 0;
    for (uint32_t f = 0; f < kBatchFrames; ++f)
    {
        writeFrameHeader(raw + offset, kBatchFrameLength, kMuxFlagData, kTestChildCid);
        offset += kMuxFrameLength;
        for (uint32_t b = 0; b < kBatchFrameLength; ++b)
        {
            raw[offset + b] = patternByte(produced + b);
        }
        offset += kBatchFrameLength;
        produced += kBatchFrameLength;
    }

    muxserverTunnelUpStreamPayload(fixture.mux, fixture.parent_l, batch);

    twfRequire(lineIsAlive(fixture.parent_l), "the parent line was closed by a batch of complete frames");
    twfRequireEqualU32(fixture.trace.next_payload, kBatchFrames, "not every complete frame reached the child");
    twfRequireEqualU32(fixture.trace.next_payload_bytes, produced, "the drained frames lost bytes");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "a child was finished while draining legal frames");

    for (uint32_t i = 0; i < produced; ++i)
    {
        twfRequire(fixture.capture[i] == patternByte(i), "the drained frames arrived out of order");
    }

    fixtureTeardown(&fixture);
}

int main(void)
{
    caseDownstreamFraming(kMuxMaxDataFrameLength, 1, "a payload exactly at the per-frame limit stays one frame");
    caseDownstreamFraming(kMuxMaxDataFrameLength + 1U, 2, "a payload one byte over the limit becomes two frames");
    caseDownstreamFraming((3U * kMuxMaxDataFrameLength) - 5U, 3, "a payload spanning three frames is fragmented");

    caseLargeCompleteBatchIsDrained();

    printf("muxserver_frame_encoding_test: all cases passed\n");
    return 0;
}
