/*
 * MuxClient payload framing.
 *
 * An sbuf_t is not limited to one 16-bit MUX frame: sbufReserveSpace() can legitimately hand MuxClient a much
 * larger payload. That is valid data, so it is fragmented into consecutive DATA frames instead of being treated
 * as corruption. This test pins the wire result of both the single-frame path and the fragmented path, the
 * exactly-once Open frame, and the receive-side rule that a batch of complete frames is drained rather than
 * judged an overflow.
 */
#include "MuxClient/structure.h"

#include "tunnel_line_failure_harness.h"

enum
{
    kTestLargeBufferSize = 2u * 1024u * 1024u,
    kTestChildCid        = 7,
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

// Deterministic filler so a reordered or dropped fragment is visible byte for byte.
static uint8_t patternByte(uint32_t index)
{
    return (uint8_t) ((index * 31U + 17U) & 0xFFU);
}

// ---------------------------------------------------------------------------
// fixture
// ---------------------------------------------------------------------------

typedef struct muxclient_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *mux;
    tunnel_t        *next;
    line_t          *parent_l;
    line_t          *child_l;
    uint8_t         *capture;
} muxclient_fixture_t;

static void fixtureSetup(muxclient_fixture_t *fixture, uint32_t capture_capacity)
{
    memoryZero(&fixture->trace, sizeof(fixture->trace));
    twfWorkerEnvSetup(&fixture->env, kTestLargeBufferSize, kMuxFrameLength * 2);

    fixture->capture = memoryAllocate(capture_capacity);
    twfRequire(fixture->capture != NULL, "failed to allocate the neighbour capture buffer");
    fixture->trace.capture          = fixture->capture;
    fixture->trace.capture_capacity = capture_capacity;

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    // one worker slot for the unsatisfied_lines flexible array
    fixture->mux = tunnelCreate(NULL, sizeof(muxclient_tstate_t) + sizeof(line_t *), sizeof(muxclient_lstate_t));
    twfRequire(fixture->mux != NULL, "failed to create the MuxClient tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);

    tunnelBind(fixture->prev, fixture->mux);
    tunnelBind(fixture->mux, fixture->next);

    muxclient_tstate_t *ts           = tunnelGetState(fixture->mux);
    ts->concurrency_mode             = kConcurrencyModeCounter;
    ts->concurrency_capacity         = 1024;
    ts->child_buffer_limit           = kMuxDefaultChildBufferLimit;
    ts->child_buffer_pause_tolerance = kMuxDefaultChildBufferPauseTolerance;
    ts->parent_buffer_limit          = kMuxDefaultParentBufferLimit;

    fixture->parent_l = twfLineCreate(fixture->mux->lstate_size);
    fixture->child_l  = twfLineCreate(fixture->mux->lstate_size);

    muxclient_lstate_t *parent_ls = lineGetState(fixture->parent_l, fixture->mux);
    muxclient_lstate_t *child_ls  = lineGetState(fixture->child_l, fixture->mux);

    muxclientLinestateInitialize(parent_ls, fixture->parent_l, false, 0);
    muxclientLinestateInitialize(child_ls, fixture->child_l, true, kTestChildCid);
    muxclientJoinConnection(parent_ls, child_ls);
}

static void fixtureTeardown(muxclient_fixture_t *fixture)
{
    muxclient_lstate_t *parent_ls = lineGetState(fixture->parent_l, fixture->mux);
    muxclient_lstate_t *child_ls  = lineGetState(fixture->child_l, fixture->mux);

    muxclientLeaveConnection(child_ls);
    muxclientLinestateDestroy(child_ls);
    muxclientLinestateDestroy(parent_ls);

    twfRequireNoLeakedBuffers();

    twfLineDestroy(fixture->child_l);
    twfLineDestroy(fixture->parent_l);
    memoryFree(fixture->capture);
    memoryFree(fixture->prev);
    memoryFree(fixture->mux);
    memoryFree(fixture->next);
}

static sbuf_t *makePatternPayload(muxclient_fixture_t *fixture, uint32_t length)
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

static void requireReassembledPattern(const frame_view_t *frames, uint32_t frame_count, uint32_t first_data_frame,
                                      uint32_t expected_length)
{
    uint32_t consumed = 0;
    for (uint32_t i = first_data_frame; i < frame_count; ++i)
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

static void caseUpstreamFraming(uint32_t payload_length, uint32_t expected_data_frames, const char *case_name)
{
    twfSetCase(case_name);

    muxclient_fixture_t fixture;
    fixtureSetup(&fixture, payload_length + (kTestMaxFrames * kMuxFrameLength));

    // first payload of this child: exactly one Open frame, then every Data fragment
    muxclientTunnelUpStreamPayload(fixture.mux, fixture.child_l, makePatternPayload(&fixture, payload_length));

    frame_view_t frames[kTestMaxFrames];
    uint32_t     frame_count = parseFrames(fixture.capture, fixture.trace.capture_len, frames, kTestMaxFrames);

    twfRequireEqualU32(frame_count, expected_data_frames + 1U, "the first payload produced the wrong frame count");
    twfRequireEqualU32(frames[0].flags, kMuxFlagOpen, "the first frame of a new child is not an Open frame");
    twfRequireEqualU32(frames[0].length, 0, "the Open frame is not zero length");
    twfRequireEqualU32(frames[0].cid, kTestChildCid, "the Open frame carries the wrong connection id");
    requireReassembledPattern(frames, frame_count, 1, payload_length);

    // second payload of the same child: no second Open frame
    fixture.trace.capture_len = 0;
    muxclientTunnelUpStreamPayload(fixture.mux, fixture.child_l, makePatternPayload(&fixture, payload_length));

    frame_count = parseFrames(fixture.capture, fixture.trace.capture_len, frames, kTestMaxFrames);
    twfRequireEqualU32(frame_count, expected_data_frames, "the second payload produced the wrong frame count");
    for (uint32_t i = 0; i < frame_count; ++i)
    {
        twfRequire(frames[i].flags != kMuxFlagOpen, "a second Open frame was emitted for the same child");
    }
    requireReassembledPattern(frames, frame_count, 0, payload_length);

    fixtureTeardown(&fixture);
}

/*
 * A single downstream batch may legally carry far more than the read-stream limit, as long as every byte belongs
 * to a complete frame. The parser has to drain it instead of tearing the parent connection down.
 */
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

    muxclient_fixture_t fixture;
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

    muxclientTunnelDownStreamPayload(fixture.mux, fixture.parent_l, batch);

    twfRequire(lineIsAlive(fixture.parent_l), "the parent line was closed by a batch of complete frames");
    twfRequireEqualU32(fixture.trace.prev_payload, kBatchFrames, "not every complete frame reached the child");
    twfRequireEqualU32(fixture.trace.prev_payload_bytes, produced, "the drained frames lost bytes");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "a child was finished while draining legal frames");

    for (uint32_t i = 0; i < produced; ++i)
    {
        twfRequire(fixture.capture[i] == patternByte(i), "the drained frames arrived out of order");
    }

    fixtureTeardown(&fixture);
}

/*
 * A parent that dies re-entrantly while a child payload is being forwarded must not be touched again.
 */
static line_t *g_reentrant_victim_parent = NULL;

static void killParentOnPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    twf_trace_t *trace = twfTrace(t);
    ++trace->next_payload;
    trace->next_payload_bytes += sbufGetLength(buf);
    lineReuseBuffer(l, buf);

    if (g_reentrant_victim_parent != NULL)
    {
        g_reentrant_victim_parent->alive = false;
    }
}

static void caseReentrantParentCloseReturnsImmediately(void)
{
    twfSetCase("a re-entrant parent close stops the upstream payload path");

    muxclient_fixture_t fixture;
    fixtureSetup(&fixture, 4096);

    muxclient_lstate_t *parent_ls = lineGetState(fixture.parent_l, fixture.mux);

    g_reentrant_victim_parent = fixture.parent_l;
    fixture.next->fnPayloadU  = killParentOnPayload;

    muxclientTunnelUpStreamPayload(fixture.mux, fixture.child_l, makePatternPayload(&fixture, 32));

    g_reentrant_victim_parent = NULL;
    fixture.next->fnPayloadU  = twfNextPayload;

    twfRequireEqualU32(fixture.trace.next_payload, 1, "the child payload never reached the parent transport");
    twfRequire(! lineIsAlive(fixture.parent_l), "the re-entrant close did not take effect");
    twfRequire(parent_ls->last_writer == fixture.child_l,
               "the payload path reset parent state after the parent had died");
    twfRequireNoLeakedBuffers();

    // Put the line back into a shape the shared teardown can clean up.
    fixture.parent_l->alive = true;
    parent_ls->last_writer  = NULL;

    fixtureTeardown(&fixture);
}

static line_t *createPausedClientChild(muxclient_fixture_t *fixture, muxclient_lstate_t *parent_ls, mux_cid_t cid)
{
    line_t             *child_l  = twfLineCreate(fixture->mux->lstate_size);
    muxclient_lstate_t *child_ls = lineGetState(child_l, fixture->mux);

    muxclientLinestateInitialize(child_ls, child_l, true, cid);
    child_ls->paused = true;
    muxclientJoinConnection(parent_ls, child_ls);
    return child_l;
}

static void destroySurvivingClientChild(muxclient_fixture_t *fixture, line_t *child_l)
{
    muxclient_lstate_t *child_ls = lineGetState(child_l, fixture->mux);
    muxclientLeaveConnection(child_ls);
    muxclientLinestateDestroy(child_ls);
    twfLineDestroy(child_l);
}

/*
 * This shape catches the average-based policy from PR #332. The trigger is the
 * most-recently-active child and has only 20 KiB queued, while an older stalled
 * child holds 48 KiB. Three idle children pull the mean below the trigger size,
 * so a mean cut closes the trigger even though it is not the pressure source.
 */
static void caseParentBufferLimitClosesActualLargestQueue(void)
{
    twfSetCase("the parent buffer limit closes the actual largest queued child");

    enum
    {
        kIdleChildren = 3,
        kLargeQueue   = 48u * 1024u,
        kTriggerQueue = 20u * 1024u,
        kParentLimit  = 64u * 1024u
    };

    muxclient_fixture_t fixture;
    fixtureSetup(&fixture, 256);

    muxclient_tstate_t *ts         = tunnelGetState(fixture.mux);
    muxclient_lstate_t *parent_ls  = lineGetState(fixture.parent_l, fixture.mux);
    muxclient_lstate_t *trigger_ls = lineGetState(fixture.child_l, fixture.mux);

    ts->parent_buffer_limit = kParentLimit;
    trigger_ls->paused      = true;

    line_t *large_l = createPausedClientChild(&fixture, parent_ls, kTestChildCid + 1U);
    line_t *idle[kIdleChildren];
    for (uint32_t i = 0; i < (uint32_t) kIdleChildren; ++i)
    {
        idle[i] = createPausedClientChild(&fixture, parent_ls, kTestChildCid + 2U + i);
    }

    // The frame parser keeps recently active children at the front. Reinsert the
    // trigger there so the regression fails if selection merely walks from the head.
    muxclientLeaveConnection(trigger_ls);
    muxclientJoinConnection(parent_ls, trigger_ls);

    muxclient_lstate_t *large_ls = lineGetState(large_l, fixture.mux);
    twfRequire(muxclientQueueChildPayload(fixture.mux,
                                          fixture.parent_l,
                                          ts,
                                          parent_ls,
                                          large_ls,
                                          makePatternPayload(&fixture, kLargeQueue)),
               "queueing the large stalled child tore down the parent");
    twfRequireEqualU32((uint32_t) parent_ls->pending_child_data_len,
                       kLargeQueue,
                       "the first queue did not update the parent total");

    twfRequire(muxclientQueueChildPayload(fixture.mux,
                                          fixture.parent_l,
                                          ts,
                                          parent_ls,
                                          trigger_ls,
                                          makePatternPayload(&fixture, kTriggerQueue)),
               "shedding the largest child tore down the parent");

    twfRequire(lineIsAlive(fixture.parent_l), "the shared parent was closed under child queue pressure");
    twfRequire(lineIsAlive(large_l), "MuxClient must not destroy the borrowed child line");
    twfRequireLineStateZeroed(large_l, fixture.mux, "the actual largest child was not shed");
    twfRequire(trigger_ls->parent == parent_ls, "the smaller trigger child was shed instead of the largest queue");
    twfRequireEqualU32(parent_ls->children_count, 1U + kIdleChildren, "the shed child was not unlinked exactly once");
    twfRequireEqualU32((uint32_t) parent_ls->pending_child_data_len,
                       kTriggerQueue,
                       "closing the largest child did not release its queued bytes");
    twfRequireEqualText(fixture.trace.seq,
                        "Pf",
                        "queue pressure must emit one Close and child Finish without pausing the parent");

    frame_view_t frames[2];
    uint32_t     frame_count = parseFrames(fixture.capture, fixture.trace.capture_len, frames, 2);
    twfRequireEqualU32(frame_count, 1, "parent shedding emitted more than one control frame");
    twfRequireEqualU32(frames[0].flags, kMuxFlagClose, "parent shedding did not emit a Close frame");
    twfRequireEqualU32(frames[0].cid, kTestChildCid + 1U, "parent shedding announced the wrong child cid");

    for (uint32_t i = 0; i < (uint32_t) kIdleChildren; ++i)
    {
        destroySurvivingClientChild(&fixture, idle[i]);
    }
    twfLineDestroy(large_l);
    fixtureTeardown(&fixture);
}

static void caseParentBufferLimitCanBeDisabled(void)
{
    twfSetCase("parent-buffer-limit zero disables aggregate shedding");

    enum
    {
        kQueuedBytes = 256u * 1024u
    };

    muxclient_fixture_t fixture;
    fixtureSetup(&fixture, 32);

    muxclient_tstate_t *ts        = tunnelGetState(fixture.mux);
    muxclient_lstate_t *parent_ls = lineGetState(fixture.parent_l, fixture.mux);
    muxclient_lstate_t *child_ls  = lineGetState(fixture.child_l, fixture.mux);

    ts->parent_buffer_limit = kMuxParentBufferLimitUnlimited;
    child_ls->paused        = true;

    twfRequire(muxclientQueueChildPayload(fixture.mux,
                                          fixture.parent_l,
                                          ts,
                                          parent_ls,
                                          child_ls,
                                          makePatternPayload(&fixture, kQueuedBytes)),
               "an unlimited parent budget tore down the parent");
    twfRequire(child_ls->parent == parent_ls, "an unlimited parent budget shed its child");
    twfRequireEqualU32((uint32_t) parent_ls->pending_child_data_len,
                       kQueuedBytes,
                       "the unlimited parent budget lost queued-byte accounting");
    twfRequireEqualText(fixture.trace.seq, "", "an unlimited parent budget emitted flow or close callbacks");

    fixtureTeardown(&fixture);
}

int main(void)
{
    caseUpstreamFraming(kMuxMaxDataFrameLength, 1, "a payload exactly at the per-frame limit stays one frame");
    caseUpstreamFraming(kMuxMaxDataFrameLength + 1U, 2, "a payload one byte over the limit becomes two frames");
    caseUpstreamFraming((3U * kMuxMaxDataFrameLength) - 5U, 3, "a payload spanning three frames is fragmented");

    caseLargeCompleteBatchIsDrained();
    caseReentrantParentCloseReturnsImmediately();
    caseParentBufferLimitClosesActualLargestQueue();
    caseParentBufferLimitCanBeDisabled();

    printf("muxclient_frame_encoding_test: all cases passed\n");
    return 0;
}
