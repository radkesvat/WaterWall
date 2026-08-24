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
    twf_line_pool_t  lines;
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

    muxclient_tstate_t *ts            = tunnelGetState(fixture->mux);
    ts->concurrency_mode              = kConcurrencyModeCounter;
    ts->concurrency_capacity          = 1024;
    ts->child_buffer_limit            = kMuxDefaultChildBufferLimit;
    ts->child_buffer_pause_tolerance  = kMuxDefaultChildBufferPauseTolerance;
    ts->child_buffer_resume_threshold = kMuxDefaultChildBufferResumeThreshold;
    ts->parent_buffer_limit           = kMuxDefaultParentBufferLimit;
    ts->detached_buffer_limit         = kMuxMinimumDetachedBufferLimit;
    ts->detached_child_limit          = kMuxMinimumDetachedChildLimit;
    ts->workers_count                 = 1;
    ts->detached_child_counts         = memoryAllocateZero(sizeof(*ts->detached_child_counts));
    ts->detached_queued_bytes         = memoryAllocateZero(sizeof(*ts->detached_queued_bytes));
    twfRequire(ts->detached_child_counts != NULL && ts->detached_queued_bytes != NULL,
               "failed to allocate detached MuxClient accounting");

    twfLinePoolSetup(&fixture->lines, fixture->mux->lstate_size, 16);
    fixture->parent_l = twfLinePoolCreateLine(&fixture->lines);
    fixture->child_l  = twfLinePoolCreateLine(&fixture->lines);

    muxclient_lstate_t *parent_ls = lineGetState(fixture->parent_l, fixture->mux);
    muxclient_lstate_t *child_ls  = lineGetState(fixture->child_l, fixture->mux);

    muxclientLinestateInitialize(parent_ls, fixture->parent_l, false, 0);
    muxclientLinestateInitialize(child_ls, fixture->child_l, true, kTestChildCid);
    muxclientJoinConnection(parent_ls, child_ls);
}

static void fixtureTeardown(muxclient_fixture_t *fixture)
{
    muxclient_lstate_t *parent_ls = fixture->parent_l != NULL ? lineGetState(fixture->parent_l, fixture->mux) : NULL;
    muxclient_lstate_t *child_ls  = lineGetState(fixture->child_l, fixture->mux);

    if (child_ls->l != NULL)
    {
        if (child_ls->parent != NULL)
        {
            muxclientLeaveConnection(child_ls);
            discard muxclientReleaseParentInputForChildClose(fixture->mux, fixture->parent_l, parent_ls, child_ls);
        }
        muxclientLinestateDestroy(child_ls);
    }
    if (parent_ls != NULL && parent_ls->l != NULL)
    {
        muxclientLinestateDestroy(parent_ls);
    }

    twfRequireNoLeakedBuffers();

    if (lineIsAlive(fixture->child_l))
    {
        lineDestroy(fixture->child_l);
    }
    if (fixture->parent_l != NULL && lineIsAlive(fixture->parent_l))
    {
        lineDestroy(fixture->parent_l);
    }
    muxclient_tstate_t *ts = tunnelGetState(fixture->mux);
    memoryFree(ts->detached_child_counts);
    memoryFree(ts->detached_queued_bytes);
    memoryFree(fixture->capture);
    memoryFree(fixture->prev);
    memoryFree(fixture->mux);
    memoryFree(fixture->next);
    twfLinePoolTeardown(&fixture->lines);
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
    line_t             *child_l  = twfLinePoolCreateLine(&fixture->lines);
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
    muxclient_lstate_t *parent_ls = lineGetState(fixture->parent_l, fixture->mux);
    discard             muxclientReleaseParentInputForChildClose(fixture->mux, fixture->parent_l, parent_ls, child_ls);
    muxclientLinestateDestroy(child_ls);
    lineDestroy(child_l);
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
    twfRequire(muxclientQueueChildPayload(
                   fixture.mux, fixture.parent_l, ts, parent_ls, large_ls, makePatternPayload(&fixture, kLargeQueue)),
               "queueing the large stalled child tore down the parent");
    twfRequireEqualU32(
        (uint32_t) parent_ls->pending_child_data_len, kLargeQueue, "the first queue did not update the parent total");

    twfRequire(
        muxclientQueueChildPayload(
            fixture.mux, fixture.parent_l, ts, parent_ls, trigger_ls, makePatternPayload(&fixture, kTriggerQueue)),
        "shedding the largest child tore down the parent");

    twfRequire(lineIsAlive(fixture.parent_l), "the shared parent was closed under child queue pressure");
    twfRequire(lineIsAlive(large_l), "MuxClient must not destroy the borrowed child line");
    twfRequireLineStateZeroed(large_l, fixture.mux, "the actual largest child was not shed");
    twfRequire(trigger_ls->parent == parent_ls, "the smaller trigger child was shed instead of the largest queue");
    twfRequireEqualU32(parent_ls->children_count, 1U + kIdleChildren, "the shed child was not unlinked exactly once");
    twfRequireEqualU32((uint32_t) parent_ls->pending_child_data_len,
                       kTriggerQueue,
                       "closing the largest child did not release its queued bytes");
    twfRequireEqualText(
        fixture.trace.seq, "Pf", "queue pressure must emit one Close and child Finish without pausing the parent");

    frame_view_t frames[2];
    uint32_t     frame_count = parseFrames(fixture.capture, fixture.trace.capture_len, frames, 2);
    twfRequireEqualU32(frame_count, 1, "parent shedding emitted more than one control frame");
    twfRequireEqualU32(frames[0].flags, kMuxFlagClose, "parent shedding did not emit a Close frame");
    twfRequireEqualU32(frames[0].cid, kTestChildCid + 1U, "parent shedding announced the wrong child cid");

    for (uint32_t i = 0; i < (uint32_t) kIdleChildren; ++i)
    {
        destroySurvivingClientChild(&fixture, idle[i]);
    }
    lineDestroy(large_l);
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

    twfRequire(muxclientQueueChildPayload(
                   fixture.mux, fixture.parent_l, ts, parent_ls, child_ls, makePatternPayload(&fixture, kQueuedBytes)),
               "an unlimited parent budget tore down the parent");
    twfRequire(child_ls->parent == parent_ls, "an unlimited parent budget shed its child");
    twfRequireEqualU32((uint32_t) parent_ls->pending_child_data_len,
                       kQueuedBytes,
                       "the unlimited parent budget lost queued-byte accounting");
    twfRequireEqualText(fixture.trace.seq, "", "an unlimited parent budget emitted flow or close callbacks");

    fixtureTeardown(&fixture);
}

static sbuf_t *makeControlFrame(muxclient_fixture_t *fixture, uint8_t flag, mux_cid_t cid)
{
    sbuf_t *buf = bufferpoolGetLargeBuffer(fixture->env.pool);
    buf         = sbufReserveSpace(buf, kMuxFrameLength);
    sbufSetLength(buf, kMuxFrameLength);
    writeFrameHeader(sbufGetMutablePtr(buf), 0, flag, cid);
    return buf;
}

static uint32_t appendInputFrame(uint8_t *raw, uint32_t offset, mux_cid_t cid, uint8_t flag, uint32_t length,
                                 uint8_t fill)
{
    writeFrameHeader(raw + offset, length, flag, cid);
    offset += kMuxFrameLength;
    if (length > 0)
    {
        memorySet(raw + offset, fill, length);
        offset += length;
    }
    return offset;
}

static void queueTwoPausedClientPayloads(muxclient_fixture_t *fixture, uint32_t first_len, uint32_t second_len)
{
    muxclient_tstate_t *ts        = tunnelGetState(fixture->mux);
    muxclient_lstate_t *parent_ls = lineGetState(fixture->parent_l, fixture->mux);
    muxclient_lstate_t *child_ls  = lineGetState(fixture->child_l, fixture->mux);

    child_ls->paused          = true;
    child_ls->open_frame_sent = true;
    twfRequire(muxclientQueueChildPayload(
                   fixture->mux, fixture->parent_l, ts, parent_ls, child_ls, makePatternPayload(fixture, first_len)),
               "queueing the first paused child payload failed");
    twfRequire(muxclientQueueChildPayload(
                   fixture->mux, fixture->parent_l, ts, parent_ls, child_ls, makePatternPayload(fixture, second_len)),
               "queueing the second paused child payload failed");
}

static void caseConfiguredResumeThresholdControlsFlowResume(void)
{
    twfSetCase("MuxClient configured child resume threshold controls FlowResume timing");

    enum
    {
        kFirst     = 10,
        kSecond    = 10,
        kThreshold = 5,
    };

    muxclient_fixture_t fixture;
    fixtureSetup(&fixture, kFirst + kSecond + kMuxFrameLength);

    muxclient_tstate_t *ts            = tunnelGetState(fixture.mux);
    muxclient_lstate_t *child_ls      = lineGetState(fixture.child_l, fixture.mux);
    ts->child_buffer_resume_threshold = kThreshold;
    child_ls->flow_paused_sent        = true;
    queueTwoPausedClientPayloads(&fixture, kFirst, kSecond);

    muxclientTunnelUpStreamResume(fixture.mux, fixture.child_l);

    twfRequireEqualText(fixture.trace.seq, "ppP", "MuxClient sent FlowResume above its configured threshold");
    twfRequireEqualU32(fixture.trace.prev_payload, 2, "MuxClient did not drain both queued child payloads");
    twfRequireEqualU32(fixture.trace.next_payload, 1, "MuxClient did not send exactly one FlowResume frame");
    twfRequire(fixture.capture[kFirst + kSecond + 2U] == kMuxFlagFlowResume,
               "MuxClient emitted the wrong control frame at its configured resume threshold");
    twfRequire(! child_ls->flow_paused_sent, "MuxClient retained its sent-pause latch after FlowResume");

    fixtureTeardown(&fixture);
}

static void casePeerCloseWaitsForResume(void)
{
    twfSetCase("MuxClient peer Close waits for a paused child queue to drain");

    enum
    {
        kFirst  = 13,
        kSecond = 17
    };
    muxclient_fixture_t fixture;
    fixtureSetup(&fixture, 128);
    queueTwoPausedClientPayloads(&fixture, kFirst, kSecond);

    muxclient_lstate_t *parent_ls = lineGetState(fixture.parent_l, fixture.mux);
    muxclient_lstate_t *child_ls  = lineGetState(fixture.child_l, fixture.mux);

    muxclientTunnelDownStreamPayload(
        fixture.mux, fixture.parent_l, makeControlFrame(&fixture, kMuxFlagClose, kTestChildCid));

    twfRequireEqualU32(fixture.trace.prev_payload, 0, "peer Close forced Payload through child Pause");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "peer Close finished the child before its queue drained");
    twfRequire(child_ls->close_state == kMuxClientChildClosePeerDraining,
               "peer Close did not publish the draining state");
    twfRequire(child_ls->parent == parent_ls, "a blocked peer-close child was removed from CID routing");
    twfRequireEqualU32((uint32_t) parent_ls->pending_child_data_len,
                       kFirst + kSecond,
                       "peer Close changed queued-byte accounting before delivery");

    muxclientTunnelUpStreamResume(fixture.mux, fixture.child_l);

    twfRequireEqualText(fixture.trace.seq, "uppf", "peer Close did not preserve Pause, FIFO Payload, Finish order");
    twfRequireEqualU32(fixture.trace.prev_payload_bytes, kFirst + kSecond, "peer-close drain lost queued bytes");
    twfRequireEqualU32(parent_ls->children_count, 0, "peer-close completion left the child attached");
    twfRequireEqualU32(
        (uint32_t) parent_ls->pending_child_data_len, 0, "peer-close completion left parent bytes accounted");
    twfRequireLineStateZeroed(fixture.child_l, fixture.mux, "peer-close completion left child state alive");

    fixtureTeardown(&fixture);
}

static void casePeerCloseDropsLateFramesAndKeepsSiblingProgress(void)
{
    twfSetCase("MuxClient drops same-batch late frames for a draining cid while a sibling progresses");

    enum
    {
        kFirst       = 11,
        kLate        = 13,
        kSibling     = 17,
        kSiblingCid  = kTestChildCid + 1U,
        kBatchFrames = 7,
        kBatchBytes  = (kBatchFrames * kMuxFrameLength) + kFirst + kLate + kSibling
    };

    muxclient_fixture_t fixture;
    fixtureSetup(&fixture, kFirst + kSibling);

    muxclient_lstate_t *parent_ls = lineGetState(fixture.parent_l, fixture.mux);
    muxclient_lstate_t *child_ls  = lineGetState(fixture.child_l, fixture.mux);
    child_ls->paused              = true;
    child_ls->open_frame_sent     = true;

    line_t             *sibling_l  = createPausedClientChild(&fixture, parent_ls, kSiblingCid);
    muxclient_lstate_t *sibling_ls = lineGetState(sibling_l, fixture.mux);
    sibling_ls->paused             = false;
    sibling_ls->open_frame_sent    = true;

    sbuf_t *batch = bufferpoolGetLargeBuffer(fixture.env.pool);
    batch         = sbufReserveSpace(batch, kBatchBytes);
    sbufSetLength(batch, kBatchBytes);
    uint8_t *raw    = sbufGetMutablePtr(batch);
    uint32_t offset = 0;
    offset          = appendInputFrame(raw, offset, kTestChildCid, kMuxFlagData, kFirst, 0x31);
    offset          = appendInputFrame(raw, offset, kTestChildCid, kMuxFlagClose, 0, 0);
    offset          = appendInputFrame(raw, offset, kTestChildCid, kMuxFlagData, kLate, 0x7e);
    offset          = appendInputFrame(raw, offset, kTestChildCid, kMuxFlagFlowPause, 0, 0);
    offset          = appendInputFrame(raw, offset, kTestChildCid, kMuxFlagFlowResume, 0, 0);
    offset          = appendInputFrame(raw, offset, kTestChildCid, kMuxFlagClose, 0, 0);
    offset          = appendInputFrame(raw, offset, kSiblingCid, kMuxFlagData, kSibling, 0x52);
    twfRequireEqualU32(offset, kBatchBytes, "the mixed MuxClient input batch has the wrong size");

    muxclientTunnelDownStreamPayload(fixture.mux, fixture.parent_l, batch);

    twfRequire(lineIsAlive(fixture.parent_l), "late terminal frames killed the shared parent");
    twfRequire(child_ls->close_state == kMuxClientChildClosePeerDraining,
               "same-batch Close did not retain the terminal cid for ordered draining");
    twfRequire(child_ls->parent == parent_ls, "same-batch Close removed the blocked cid from routing");
    twfRequire(! child_ls->peer_flow_paused && ! child_ls->parent_write_paused,
               "late flow-control frames changed terminal child source state");
    twfRequireEqualU32((uint32_t) bufferqueueGetBufLen(&child_ls->pending_child_data),
                       kFirst,
                       "late Data changed the terminal child's retained FIFO");
    twfRequireEqualU32(
        (uint32_t) parent_ls->pending_child_data_len, kFirst, "late Data changed parent queued-byte accounting");
    twfRequireEqualU32(fixture.trace.prev_payload, 1, "the writable sibling did not progress in the same parser pass");
    twfRequireEqualU32(
        fixture.trace.prev_payload_bytes, kSibling, "late terminal Data was delivered or sibling bytes were lost");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "duplicate Close completed the blocked child early");

    muxclientTunnelUpStreamResume(fixture.mux, fixture.child_l);

    twfRequireEqualU32(fixture.trace.prev_payload, 2, "the retained pre-Close payload was not delivered once");
    twfRequireEqualU32(fixture.trace.prev_payload_bytes,
                       kSibling + kFirst,
                       "terminal drain delivered bytes after Close or lost pre-Close bytes");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "terminal drain did not finish exactly once");
    twfRequireLineStateZeroed(fixture.child_l, fixture.mux, "terminal child state survived the ordered drain");
    for (uint32_t i = 0; i < kSibling; ++i)
    {
        twfRequire(fixture.capture[i] == 0x52, "the sibling payload was reordered or corrupted");
    }
    for (uint32_t i = kSibling; i < kSibling + kFirst; ++i)
    {
        twfRequire(fixture.capture[i] == 0x31, "the pre-Close payload was reordered or corrupted");
    }

    destroySurvivingClientChild(&fixture, sibling_l);
    fixtureTeardown(&fixture);
}

static void caseParentLossDetachesAndDrainsBorrowedChild(void)
{
    twfSetCase("MuxClient parent loss detaches a paused borrowed child until Resume");

    enum
    {
        kFirst  = 19,
        kSecond = 23
    };
    muxclient_fixture_t fixture;
    fixtureSetup(&fixture, 128);
    queueTwoPausedClientPayloads(&fixture, kFirst, kSecond);

    muxclient_tstate_t *ts       = tunnelGetState(fixture.mux);
    muxclient_lstate_t *child_ls = lineGetState(fixture.child_l, fixture.mux);
    ts->unsatisfied_lines[0]     = fixture.parent_l;

    lineLock(fixture.parent_l);
    muxclientTunnelDownStreamFinish(fixture.mux, fixture.parent_l);

    twfRequire(! lineIsAlive(fixture.parent_l), "MuxClient parent Finish left its owned parent alive");
    twfRequireLineStateZeroed(fixture.parent_l, fixture.mux, "MuxClient parent Finish retained parent state");
    twfRequire(lineIsAlive(fixture.child_l), "MuxClient destroyed a borrowed detached child");
    twfRequire(child_ls->is_child, "detachment changed the immutable child role");
    twfRequire(child_ls->parent == NULL, "detached borrowed child retained the dead parent pointer");
    twfRequire(child_ls->close_state == kMuxClientChildCloseParentGoneDraining,
               "parent loss did not publish detached drain state");
    twfRequireEqualU32(ts->detached_child_counts[0], 1, "detached borrowed child count is wrong");
    twfRequireEqualU32(
        (uint32_t) ts->detached_queued_bytes[0], kFirst + kSecond, "detached borrowed byte accounting is wrong");
    twfRequireEqualU32(fixture.trace.prev_payload, 0, "parent loss forced Payload through child Pause");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "parent loss finished a blocked child early");

    lineUnlock(fixture.parent_l);
    fixture.parent_l = NULL;

    muxclientTunnelUpStreamResume(fixture.mux, fixture.child_l);

    twfRequireEqualText(fixture.trace.seq, "uppf", "detached borrowed drain did not preserve callback order");
    twfRequireEqualU32(fixture.trace.prev_payload_bytes, kFirst + kSecond, "detached borrowed drain lost bytes");
    twfRequireEqualU32(ts->detached_child_counts[0], 0, "detached borrowed count survived completion");
    twfRequireEqualU32((uint32_t) ts->detached_queued_bytes[0], 0, "detached borrowed bytes survived completion");
    twfRequire(lineIsAlive(fixture.child_l), "MuxClient destroyed its borrowed child after detached drain");
    twfRequireLineStateZeroed(fixture.child_l, fixture.mux, "detached borrowed child state survived completion");

    fixtureTeardown(&fixture);
}

static void caseDetachedConfiguration(void)
{
    twfSetCase("MuxClient detached backlog configuration follows RAM profile and validates overrides");

    static const struct
    {
        uint32_t ram_profile;
        uint32_t buffer_limit;
        uint32_t child_limit;
    } profiles[] = {
        {kRamProfileS1Memory, 32U * 1024U * 1024U, 4096},
        {kRamProfileS2Memory, 77U * 1024U * 1024U, 5677},
        {kRamProfileM1Memory, 122U * 1024U * 1024U, 7258},
        {kRamProfileM2Memory, 166U * 1024U * 1024U, 8838},
        {kRamProfileL1Memory, 211U * 1024U * 1024U, 10419},
        {kRamProfileL2Memory, 256U * 1024U * 1024U, 12000},
    };

    const uint32_t previous_ram_profile = GSTATE.ram_profile;
    node_t         node                 = {0};

    for (size_t i = 0; i < sizeof(profiles) / sizeof(profiles[0]); ++i)
    {
        GSTATE.ram_profile = profiles[i].ram_profile;
        cJSON *settings    = cJSON_Parse("{\"mode\":\"counter\",\"connection-capacity\":1}");
        twfRequire(settings != NULL, "failed to create default MuxClient settings");
        node.node_settings_json = settings;

        tunnel_t *mux = muxclientTunnelCreate(&node);
        twfRequire(mux != NULL, "profile-derived detached MuxClient settings were rejected");
        muxclient_tstate_t *ts = tunnelGetState(mux);
        twfRequireEqualU32(
            ts->detached_buffer_limit, profiles[i].buffer_limit, "profile-derived MuxClient byte limit drifted");
        twfRequireEqualU32(
            ts->detached_child_limit, profiles[i].child_limit, "profile-derived MuxClient child limit drifted");
        twfRequireEqualU32(ts->child_buffer_resume_threshold,
                           kMuxDefaultChildBufferResumeThreshold,
                           "default MuxClient child resume threshold drifted");
        twfRequireEqualU32(
            ts->max_children, kMuxDefaultMaxChildrenPerParent, "default MuxClient per-parent child limit drifted");
        muxclientTunnelDestroy(mux, wwLifecycleProcessShutdown());
        cJSON_Delete(settings);
    }

    GSTATE.ram_profile = kRamProfileL2Memory;
    cJSON *settings    = cJSON_Parse("{\"mode\":\"counter\",\"connection-capacity\":1,"
                                     "\"child-buffer-limit\":1000,\"child-buffer-resume-threshold\":2000,"
                                     "\"detached-buffer-limit\":0,\"detached-child-limit\":7}");
    twfRequire(settings != NULL, "failed to create explicit MuxClient settings");
    node.node_settings_json = settings;
    tunnel_t *mux           = muxclientTunnelCreate(&node);
    twfRequire(mux != NULL, "explicit detached MuxClient settings were rejected");
    muxclient_tstate_t *ts = tunnelGetState(mux);
    twfRequireEqualU32(ts->detached_buffer_limit, 0, "MuxClient zero byte limit was not preserved");
    twfRequireEqualU32(ts->detached_child_limit, 7, "MuxClient explicit child limit was not preserved");
    twfRequireEqualU32(
        ts->child_buffer_resume_threshold, 1000, "MuxClient child resume threshold was not capped to its buffer limit");
    muxclientTunnelDestroy(mux, wwLifecycleProcessShutdown());
    cJSON_Delete(settings);

    settings = cJSON_Parse("{\"mode\":\"counter\",\"connection-capacity\":1,"
                           "\"detached-buffer-limit\":-1}");
    twfRequire(settings != NULL, "failed to create invalid MuxClient settings");
    node.node_settings_json = settings;
    twfRequire(muxclientTunnelCreate(&node) == NULL, "negative detached MuxClient byte limit was accepted");
    cJSON_Delete(settings);

    settings = cJSON_Parse("{\"mode\":\"counter\",\"connection-capacity\":1,"
                           "\"child-buffer-resume-threshold\":0}");
    twfRequire(settings != NULL, "failed to create invalid MuxClient resume-threshold settings");
    node.node_settings_json = settings;
    twfRequire(muxclientTunnelCreate(&node) == NULL, "zero MuxClient child resume threshold was accepted");
    cJSON_Delete(settings);

    settings = cJSON_Parse("{\"mode\":\"counter\",\"connection-capacity\":100,\"max-children\":9}");
    twfRequire(settings != NULL, "failed to create explicit MuxClient max-children settings");
    node.node_settings_json = settings;
    mux                     = muxclientTunnelCreate(&node);
    twfRequire(mux != NULL, "valid MuxClient max-children setting was rejected");
    ts = tunnelGetState(mux);
    twfRequireEqualU32(ts->max_children, 9, "MuxClient max-children override was not preserved");
    muxclientTunnelDestroy(mux, wwLifecycleProcessShutdown());
    cJSON_Delete(settings);

    static const char *const invalid_max_children[] = {
        "{\"mode\":\"counter\",\"connection-capacity\":1,\"max-children\":0}",
        "{\"mode\":\"counter\",\"connection-capacity\":1,\"max-children\":-1}",
        "{\"mode\":\"counter\",\"connection-capacity\":1,\"max-children\":1.5}",
        "{\"mode\":\"counter\",\"connection-capacity\":1,\"max-children\":\"9\"}",
    };
    for (size_t i = 0; i < ARRAY_SIZE(invalid_max_children); ++i)
    {
        settings = cJSON_Parse(invalid_max_children[i]);
        twfRequire(settings != NULL, "failed to create invalid MuxClient max-children settings");
        node.node_settings_json = settings;
        twfRequire(muxclientTunnelCreate(&node) == NULL, "invalid MuxClient max-children setting was accepted");
        cJSON_Delete(settings);
    }

    GSTATE.ram_profile = previous_ram_profile;
}

static void caseDetachedBorrowedLocalFinishReleasesAccounting(void)
{
    twfSetCase("MuxClient detached borrowed child Finish releases residual accounting");

    muxclient_fixture_t fixture;
    fixtureSetup(&fixture, 64);
    queueTwoPausedClientPayloads(&fixture, 11, 29);

    muxclient_tstate_t *ts = tunnelGetState(fixture.mux);
    lineLock(fixture.parent_l);
    muxclientTunnelDownStreamFinish(fixture.mux, fixture.parent_l);
    lineUnlock(fixture.parent_l);
    fixture.parent_l = NULL;

    muxclientTunnelUpStreamFinish(fixture.mux, fixture.child_l);

    twfRequire(lineIsAlive(fixture.child_l), "MuxClient destroyed its borrowed child on local Finish");
    twfRequireEqualU32(fixture.trace.prev_payload, 0, "detached local Finish forwarded residual Payload");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "detached local Finish reflected Finish toward its sender");
    twfRequireEqualU32(ts->detached_child_counts[0], 0, "detached local Finish retained borrowed count");
    twfRequireEqualU32((uint32_t) ts->detached_queued_bytes[0], 0, "detached local Finish retained borrowed bytes");
    twfRequireLineStateZeroed(fixture.child_l, fixture.mux, "detached local Finish retained MuxClient state");

    muxclientTunnelOnWorkerStop(fixture.mux, 0, wwLifecycleProcessShutdown());
    fixtureTeardown(&fixture);
}

static line_t *createClientParent(muxclient_fixture_t *fixture)
{
    line_t *parent_l = twfLinePoolCreateLine(&fixture->lines);
    muxclientLinestateInitialize(lineGetState(parent_l, fixture->mux), parent_l, false, 0);
    return parent_l;
}

static line_t *createClientChildOnParent(muxclient_fixture_t *fixture, line_t *parent_l, mux_cid_t cid,
                                         uint32_t queued_bytes)
{
    line_t             *child_l   = twfLinePoolCreateLine(&fixture->lines);
    muxclient_lstate_t *parent_ls = lineGetState(parent_l, fixture->mux);
    muxclient_lstate_t *child_ls  = lineGetState(child_l, fixture->mux);
    muxclientLinestateInitialize(child_ls, child_l, true, cid);
    child_ls->paused          = true;
    child_ls->open_frame_sent = true;
    muxclientJoinConnection(parent_ls, child_ls);
    twfRequire(muxclientQueueChildPayload(fixture->mux,
                                          parent_l,
                                          tunnelGetState(fixture->mux),
                                          parent_ls,
                                          child_ls,
                                          makePatternPayload(fixture, queued_bytes)),
               "failed to queue a detached-limit MuxClient child");
    return child_l;
}

static void detachClientParent(muxclient_fixture_t *fixture, line_t *parent_l)
{
    lineLock(parent_l);
    muxclientTunnelDownStreamFinish(fixture->mux, parent_l);
    twfRequire(! lineIsAlive(parent_l), "MuxClient did not destroy an owned detached-limit parent");
    twfRequireLineStateZeroed(parent_l, fixture->mux, "detached-limit parent state survived parent loss");
    lineUnlock(parent_l);
}

static void runMuxclientDetachedAggregateLimitCase(bool unlimited_bytes, bool count_limit)
{
    const char *case_name = count_limit       ? "MuxClient detached count limit aborts only the new borrowed child"
                            : unlimited_bytes ? "MuxClient detached byte limit zero retains both borrowed children"
                                              : "MuxClient detached byte limit aborts only the new borrowed child";
    twfSetCase(case_name);

    enum
    {
        kOlderBytes = 23,
        kNewBytes   = 31
    };

    muxclient_fixture_t fixture;
    fixtureSetup(&fixture, kOlderBytes + kNewBytes);

    muxclient_tstate_t *ts       = tunnelGetState(fixture.mux);
    muxclient_lstate_t *older_ls = lineGetState(fixture.child_l, fixture.mux);
    older_ls->paused             = true;
    older_ls->open_frame_sent    = true;
    twfRequire(muxclientQueueChildPayload(fixture.mux,
                                          fixture.parent_l,
                                          ts,
                                          lineGetState(fixture.parent_l, fixture.mux),
                                          older_ls,
                                          makePatternPayload(&fixture, kOlderBytes)),
               "failed to queue the older detached MuxClient child");

    line_t *older_parent = fixture.parent_l;
    detachClientParent(&fixture, older_parent);
    fixture.parent_l = NULL;
    twfRequireEqualU32(ts->detached_child_counts[0], 1, "older detached MuxClient child was not retained");
    twfRequireEqualU32(
        (uint32_t) ts->detached_queued_bytes[0], kOlderBytes, "older detached MuxClient bytes were not retained");

    line_t *new_parent = createClientParent(&fixture);
    line_t *new_child  = createClientChildOnParent(&fixture, new_parent, kTestChildCid + 1U, kNewBytes);

    ts->detached_buffer_limit = count_limit || unlimited_bytes ? kMuxDetachedLimitUnlimited : kOlderBytes + kNewBytes;
    ts->detached_child_limit  = count_limit ? 2 : kMuxDetachedLimitUnlimited;
    detachClientParent(&fixture, new_parent);

    muxclient_lstate_t *new_ls = lineGetState(new_child, fixture.mux);
    if (unlimited_bytes)
    {
        twfRequire(new_ls->close_state == kMuxClientChildCloseParentGoneDraining,
                   "zero detached byte limit rejected the new child");
        twfRequireEqualU32(ts->detached_child_counts[0], 2, "zero detached byte limit lost a child");
        twfRequireEqualU32((uint32_t) ts->detached_queued_bytes[0],
                           kOlderBytes + kNewBytes,
                           "zero detached byte limit lost queued-byte accounting");
        muxclientTunnelUpStreamResume(fixture.mux, new_child);
        twfRequireLineStateZeroed(new_child, fixture.mux, "unlimited detached child did not drain normally");
    }
    else
    {
        twfRequireLineStateZeroed(new_child, fixture.mux, "detached aggregate limit retained the rejected child");
        twfRequireEqualU32(ts->detached_child_counts[0], 1, "detached aggregate limit removed the older child");
        twfRequireEqualU32((uint32_t) ts->detached_queued_bytes[0],
                           kOlderBytes,
                           "detached aggregate limit changed the older child's bytes");
    }

    muxclientTunnelUpStreamResume(fixture.mux, fixture.child_l);
    twfRequireLineStateZeroed(fixture.child_l, fixture.mux, "older detached child did not drain after rejection");
    twfRequireEqualU32(ts->detached_child_counts[0], 0, "MuxClient detached count survived aggregate-limit drain");
    twfRequireEqualU32(
        (uint32_t) ts->detached_queued_bytes[0], 0, "MuxClient detached bytes survived aggregate-limit drain");
    twfRequire(lineIsAlive(new_child), "MuxClient destroyed a borrowed rejected or drained child");

    lineDestroy(new_child);
    fixtureTeardown(&fixture);
}

static tunnel_t *g_reentrant_pause_client_mux = NULL;

static void pauseClientChildAfterFirstPayload(tunnel_t *prev, line_t *child_l, sbuf_t *buf)
{
    twfPrevPayload(prev, child_l, buf);
    if (g_reentrant_pause_client_mux != NULL)
    {
        tunnel_t *mux                = g_reentrant_pause_client_mux;
        g_reentrant_pause_client_mux = NULL;
        muxclientTunnelUpStreamPause(mux, child_l);
    }
}

static void runMuxclientReentrantPauseCase(bool parent_loss)
{
    twfSetCase(parent_loss ? "MuxClient detached drain stops on a re-entrant child Pause"
                           : "MuxClient attached peer-Close drain stops on a re-entrant child Pause");

    enum
    {
        kFirst  = 17,
        kSecond = 37
    };
    muxclient_fixture_t fixture;
    fixtureSetup(&fixture, kFirst + kSecond);
    queueTwoPausedClientPayloads(&fixture, kFirst, kSecond);

    muxclient_tstate_t *ts       = tunnelGetState(fixture.mux);
    muxclient_lstate_t *child_ls = lineGetState(fixture.child_l, fixture.mux);
    child_ls->paused             = false;
    fixture.prev->fnPayloadD     = pauseClientChildAfterFirstPayload;
    g_reentrant_pause_client_mux = fixture.mux;

    if (parent_loss)
    {
        lineLock(fixture.parent_l);
        muxclientTunnelDownStreamFinish(fixture.mux, fixture.parent_l);
        lineUnlock(fixture.parent_l);
        fixture.parent_l = NULL;
        twfRequireEqualU32((uint32_t) ts->detached_queued_bytes[0],
                           kSecond,
                           "re-entrant detached Pause corrupted residual byte accounting");
        twfRequireEqualU32(ts->detached_child_counts[0], 1, "re-entrant detached Pause lost child accounting");
    }
    else
    {
        muxclientTunnelDownStreamPayload(
            fixture.mux, fixture.parent_l, makeControlFrame(&fixture, kMuxFlagClose, kTestChildCid));
        muxclient_lstate_t *parent_ls = lineGetState(fixture.parent_l, fixture.mux);
        twfRequireEqualU32((uint32_t) parent_ls->pending_child_data_len,
                           kSecond,
                           "re-entrant attached Pause corrupted parent byte accounting");
        twfRequire(child_ls->parent == parent_ls, "re-entrant attached Pause detached the terminal child early");
    }

    twfRequireEqualU32(fixture.trace.prev_payload, 1, "re-entrant Pause did not stop after the first MuxClient buffer");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "re-entrant Pause allowed early MuxClient Finish");
    twfRequire(child_ls->paused, "re-entrant MuxClient Pause was not retained");
    twfRequireEqualU32((uint32_t) bufferqueueGetBufLen(&child_ls->pending_child_data),
                       kSecond,
                       "re-entrant MuxClient Pause lost the second queued buffer");

    fixture.prev->fnPayloadD = twfPrevPayload;
    muxclientTunnelUpStreamResume(fixture.mux, fixture.child_l);

    twfRequireEqualU32(fixture.trace.prev_payload, 2, "later genuine Resume did not drain the second buffer");
    twfRequireEqualU32(
        fixture.trace.prev_payload_bytes, kFirst + kSecond, "re-entrant MuxClient drain lost FIFO bytes");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "re-entrant MuxClient drain did not finish exactly once");
    twfRequireLineStateZeroed(fixture.child_l, fixture.mux, "re-entrant MuxClient drain retained child state");
    if (parent_loss)
    {
        twfRequireEqualU32(ts->detached_child_counts[0], 0, "detached re-entrant drain retained child accounting");
        twfRequireEqualU32(
            (uint32_t) ts->detached_queued_bytes[0], 0, "detached re-entrant drain retained byte accounting");
    }

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
    caseConfiguredResumeThresholdControlsFlowResume();
    casePeerCloseWaitsForResume();
    casePeerCloseDropsLateFramesAndKeepsSiblingProgress();
    caseParentLossDetachesAndDrainsBorrowedChild();
    caseDetachedConfiguration();
    caseDetachedBorrowedLocalFinishReleasesAccounting();
    runMuxclientDetachedAggregateLimitCase(false, false);
    runMuxclientDetachedAggregateLimitCase(true, false);
    runMuxclientDetachedAggregateLimitCase(false, true);
    runMuxclientReentrantPauseCase(true);
    runMuxclientReentrantPauseCase(false);

    printf("muxclient_frame_encoding_test: all cases passed\n");
    return 0;
}
