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
    twf_line_pool_t  lines;
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
    fixture->mux =
        tunnelCreate(NULL, sizeof(muxserver_tstate_t) + sizeof(muxserver_worker_state_t), sizeof(muxserver_lstate_t));
    twfRequire(fixture->mux != NULL, "failed to create the MuxServer tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);

    tunnelBind(fixture->prev, fixture->mux);
    tunnelBind(fixture->mux, fixture->next);

    muxserver_tstate_t *ts            = tunnelGetState(fixture->mux);
    ts->child_buffer_limit            = kMuxDefaultChildBufferLimit;
    ts->child_buffer_pause_tolerance  = kMuxDefaultChildBufferPauseTolerance;
    ts->child_buffer_resume_threshold = kMuxDefaultChildBufferResumeThreshold;
    ts->parent_buffer_limit           = kMuxDefaultParentBufferLimit;
    ts->detached_buffer_limit         = kMuxMinimumDetachedBufferLimit;
    ts->detached_child_limit          = kMuxMinimumDetachedChildLimit;
    ts->workers_count                 = 1;

    twfLinePoolSetup(&fixture->lines, fixture->mux->lstate_size, 8);
    fixture->parent_l = twfLinePoolCreateLine(&fixture->lines);
    fixture->child_l  = twfLinePoolCreateLine(&fixture->lines);

    muxserver_lstate_t *parent_ls = lineGetState(fixture->parent_l, fixture->mux);
    muxserver_lstate_t *child_ls  = lineGetState(fixture->child_l, fixture->mux);

    muxserverLinestateInitialize(fixture->mux, parent_ls, fixture->parent_l, false, 0);
    muxserverLinestateInitialize(fixture->mux, child_ls, fixture->child_l, true, kTestChildCid);
    muxserverJoinConnection(parent_ls, child_ls);
}

static void fixtureTeardown(muxserver_fixture_t *fixture)
{
    muxserver_lstate_t *parent_ls = fixture->parent_l != NULL ? lineGetState(fixture->parent_l, fixture->mux) : NULL;
    muxserver_lstate_t *child_ls  = fixture->child_l != NULL ? lineGetState(fixture->child_l, fixture->mux) : NULL;

    if (child_ls != NULL && child_ls->l != NULL)
    {
        muxserverLeaveConnection(child_ls);
        discard muxserverReleaseParentInputForChildClose(fixture->mux, fixture->parent_l, parent_ls, child_ls);
        muxserverLinestateDestroy(fixture->mux, child_ls);
    }
    if (parent_ls != NULL && parent_ls->l != NULL)
    {
        muxserverLinestateDestroy(fixture->mux, parent_ls);
    }

    twfRequireNoLeakedBuffers();

    if (fixture->child_l != NULL && lineIsAlive(fixture->child_l))
    {
        lineDestroy(fixture->child_l);
    }
    if (fixture->parent_l != NULL && lineIsAlive(fixture->parent_l))
    {
        lineDestroy(fixture->parent_l);
    }
    twfLinePoolTeardown(&fixture->lines);
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

static line_t *createServerSibling(muxserver_fixture_t *fixture, muxserver_lstate_t *parent_ls, mux_cid_t cid)
{
    line_t             *child_l  = twfLinePoolCreateLine(&fixture->lines);
    muxserver_lstate_t *child_ls = lineGetState(child_l, fixture->mux);
    muxserverLinestateInitialize(fixture->mux, child_ls, child_l, true, cid);
    muxserverJoinConnection(parent_ls, child_ls);
    return child_l;
}

static void destroyServerSibling(muxserver_fixture_t *fixture, line_t *child_l)
{
    muxserver_lstate_t *child_ls  = lineGetState(child_l, fixture->mux);
    muxserver_lstate_t *parent_ls = child_ls->parent;
    muxserverLeaveConnection(child_ls);
    discard muxserverReleaseParentInputForChildClose(fixture->mux, fixture->parent_l, parent_ls, child_ls);
    muxserverLinestateDestroy(fixture->mux, child_ls);
    lineDestroy(child_l);
}

static void caseConfiguredResumeThresholdControlsFlowResume(void)
{
    twfSetCase("MuxServer configured child resume threshold controls FlowResume timing");

    enum
    {
        kFirst     = 10,
        kSecond    = 10,
        kThreshold = 5,
    };

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture, kFirst + kSecond + kMuxFrameLength);

    muxserver_tstate_t *ts            = tunnelGetState(fixture.mux);
    muxserver_lstate_t *parent_ls     = lineGetState(fixture.parent_l, fixture.mux);
    muxserver_lstate_t *child_ls      = lineGetState(fixture.child_l, fixture.mux);
    ts->child_buffer_resume_threshold = kThreshold;
    child_ls->paused                  = true;
    child_ls->flow_paused_sent        = true;

    twfRequire(muxserverQueueChildPayload(
                   fixture.mux, fixture.parent_l, ts, parent_ls, child_ls, makePatternPayload(&fixture, kFirst)),
               "queueing the first paused MuxServer child payload failed");
    twfRequire(muxserverQueueChildPayload(
                   fixture.mux, fixture.parent_l, ts, parent_ls, child_ls, makePatternPayload(&fixture, kSecond)),
               "queueing the second paused MuxServer child payload failed");

    muxserverTunnelDownStreamResume(fixture.mux, fixture.child_l);

    twfRequireEqualText(fixture.trace.seq, "PPp", "MuxServer sent FlowResume above its configured threshold");
    twfRequireEqualU32(fixture.trace.next_payload, 2, "MuxServer did not drain both queued child payloads");
    twfRequireEqualU32(fixture.trace.prev_payload, 1, "MuxServer did not send exactly one FlowResume frame");
    twfRequire(fixture.capture[kFirst + kSecond + 2U] == kMuxFlagFlowResume,
               "MuxServer emitted the wrong control frame at its configured resume threshold");
    twfRequire(! child_ls->flow_paused_sent, "MuxServer retained its sent-pause latch after FlowResume");

    fixtureTeardown(&fixture);
}

static void casePerParentAdmissionRejectsWithClose(void)
{
    twfSetCase("MuxServer per-parent admission limit rejects one fresh cid without closing siblings");

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture, (3U * kMuxFrameLength) + 1U);
    muxserver_tstate_t *ts = tunnelGetState(fixture.mux);
    ts->max_children       = 1;

    const mux_cid_t rejected_cid = kTestChildCid + 100U;
    sbuf_t         *open         = bufferpoolGetLargeBuffer(fixture.env.pool);
    sbufSetLength(open, kMuxFrameLength);
    writeFrameHeader(sbufGetMutablePtr(open), 0, kMuxFlagOpen, rejected_cid);
    muxserverTunnelUpStreamPayload(fixture.mux, fixture.parent_l, open);

    muxserver_lstate_t *parent_ls = lineGetState(fixture.parent_l, fixture.mux);
    twfRequire(lineIsAlive(fixture.parent_l), "resource rejection closed the healthy borrowed parent");
    twfRequire(lineIsAlive(fixture.child_l), "resource rejection closed an admitted sibling");
    twfRequireEqualU32(parent_ls->children_count, 1, "resource rejection allocated or removed a child");
    twfRequireEqualU32(fixture.trace.prev_payload, 1, "resource rejection did not emit exactly one Close frame");
    twfRequireEqualU32(fixture.trace.next_init, 0, "resource rejection initialized a temporary child");

    frame_view_t frame;
    twfRequireEqualU32(parseFrames(fixture.capture, fixture.trace.capture_len, &frame, 1),
                       1,
                       "resource rejection emitted an invalid frame sequence");
    twfRequire(frame.flags == kMuxFlagClose && frame.cid == rejected_cid && frame.length == 0,
               "resource rejection emitted the wrong Close frame");
    fixtureTeardown(&fixture);
}

static void caseDuplicateOpenClosesParent(void)
{
    twfSetCase("MuxServer duplicate Open closes the offending parent");

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture, 1);

    sbuf_t *open = bufferpoolGetLargeBuffer(fixture.env.pool);
    sbufSetLength(open, kMuxFrameLength);
    writeFrameHeader(sbufGetMutablePtr(open), 0, kMuxFlagOpen, kTestChildCid);

    lineLock(fixture.child_l);
    muxserverTunnelUpStreamPayload(fixture.mux, fixture.parent_l, open);
    twfRequire(! lineIsAlive(fixture.child_l), "duplicate Open left the owned child alive");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "duplicate Open did not close the parent toward its owner");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "duplicate Open did not finish the admitted child");
    twfRequireLineStateZeroed(fixture.parent_l, fixture.mux, "duplicate Open retained parent MUX state");
    twfRequireLineStateZeroed(fixture.child_l, fixture.mux, "duplicate Open retained child MUX state");
    twfRequireOwnedLineReclaimed(fixture.child_l, "MuxServer duplicate Open child cleanup");
    fixture.child_l = NULL;

    fixtureTeardown(&fixture);
}

static void destroyFixtureChildIdleTable(muxserver_fixture_t *fixture)
{
    muxserver_tstate_t *ts    = tunnelGetState(fixture->mux);
    local_idle_table_t *table = ts->worker_states[0].child_idle_table;
    if (table != NULL)
    {
        twfRequireEqualU32((uint32_t) localidletableGetItemCount(table), 0, "child idle table retained an item");
        localidletableDestroy(table);
        ts->worker_states[0].child_idle_table = NULL;
    }
}

static void caseChildIdlePromotionAndImmediateRemoval(void)
{
    twfSetCase("MuxServer real payload promotes child idle timeout and explicit close removes it immediately");

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture, (3U * kMuxFrameLength) + 1U);
    muxserver_tstate_t *ts            = tunnelGetState(fixture.mux);
    muxserver_lstate_t *child_ls      = lineGetState(fixture.child_l, fixture.mux);
    ts->initial_child_idle_timeout_ms = 10;
    ts->active_child_idle_timeout_ms  = 100;
    atomicStoreRelaxed(&ts->live_children_count, 1);
    child_ls->child_slot_reserved = true;
    muxserverArmChildIdle(fixture.mux, child_ls);

    const uint64_t initial_deadline = child_ls->child_idle_item->expire_at_ms;
    sbuf_t        *empty            = bufferpoolGetLargeBuffer(fixture.env.pool);
    muxserverTunnelDownStreamPayload(fixture.mux, fixture.child_l, empty);
    twfRequire(! child_ls->child_has_payload_activity && child_ls->child_idle_item->expire_at_ms == initial_deadline,
               "zero-length Data promoted or refreshed the child idle timeout");

    sbuf_t *payload = bufferpoolGetLargeBuffer(fixture.env.pool);
    sbufSetLength(payload, 1);
    sbufGetMutablePtr(payload)[0] = 0x42;
    muxserverTunnelDownStreamPayload(fixture.mux, fixture.child_l, payload);
    twfRequire(child_ls->child_has_payload_activity && child_ls->child_idle_item->expire_at_ms > initial_deadline,
               "nonempty payload did not promote the child to the active idle timeout");

    local_idle_table_t *table = ts->worker_states[0].child_idle_table;
    twfRequireEqualU32((uint32_t) localidletableGetItemCount(table), 1, "armed child idle item is absent");
    lineLock(fixture.child_l);
    muxserverTunnelDownStreamFinish(fixture.mux, fixture.child_l);
    twfRequire(! lineIsAlive(fixture.child_l), "explicit child Finish left the owned child alive");
    twfRequireEqualU32(
        (uint32_t) localidletableGetItemCount(table), 0, "explicit close retained the long active timer item");
    twfRequireEqualU32((uint32_t) atomicLoadRelaxed(&ts->live_children_count),
                       0,
                       "explicit close retained the aggregate child reservation");
    twfRequireOwnedLineReclaimed(fixture.child_l, "MuxServer explicit close timer cleanup");
    fixture.child_l = NULL;

    destroyFixtureChildIdleTable(&fixture);
    fixtureTeardown(&fixture);
}

static void casePeerCloseDropsLateFramesAndKeepsSiblingProgress(void)
{
    twfSetCase("MuxServer drops same-batch late non-Open frames for a draining cid while a sibling progresses");

    enum
    {
        kFirst       = 11,
        kLate        = 13,
        kSibling     = 17,
        kSiblingCid  = kTestChildCid + 1U,
        kBatchFrames = 7,
        kBatchBytes  = (kBatchFrames * kMuxFrameLength) + kFirst + kLate + kSibling
    };

    muxserver_fixture_t fixture;
    fixtureSetup(&fixture, kFirst + kSibling);

    muxserver_lstate_t *parent_ls = lineGetState(fixture.parent_l, fixture.mux);
    muxserver_lstate_t *child_ls  = lineGetState(fixture.child_l, fixture.mux);
    child_ls->paused              = true;
    line_t *sibling_l             = createServerSibling(&fixture, parent_ls, kSiblingCid);

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
    twfRequireEqualU32(offset, kBatchBytes, "the mixed MuxServer input batch has the wrong size");

    muxserverTunnelUpStreamPayload(fixture.mux, fixture.parent_l, batch);

    twfRequire(lineIsAlive(fixture.parent_l), "late terminal frames killed the borrowed parent");
    twfRequire(lineIsAlive(fixture.child_l), "late control frames killed the terminal owned child");
    twfRequire(child_ls->close_state == kMuxServerChildClosePeerDraining,
               "same-batch Close did not retain the server cid for ordered draining");
    twfRequire(child_ls->parent == parent_ls, "same-batch Close removed the blocked server cid from routing");
    twfRequire(! child_ls->peer_flow_paused && ! child_ls->parent_write_paused,
               "late server flow-control frames changed terminal child source state");
    twfRequireEqualU32((uint32_t) bufferqueueGetBufLen(&child_ls->pending_child_data),
                       kFirst,
                       "late server Data changed the terminal child's retained FIFO");
    twfRequireEqualU32(
        (uint32_t) parent_ls->pending_child_data_len, kFirst, "late server Data changed parent queued-byte accounting");
    twfRequireEqualU32(parent_ls->children_count, 2, "late control frames changed the owned child inventory");
    twfRequireEqualU32(fixture.trace.next_init, 0, "late control frames initialized a replacement owned child");
    twfRequireEqualU32(
        fixture.trace.next_payload, 1, "the writable server sibling did not progress in the same parser pass");
    twfRequireEqualU32(fixture.trace.next_payload_bytes,
                       kSibling,
                       "late terminal server Data was delivered or sibling bytes were lost");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "duplicate server Close completed the blocked child early");

    lineLock(fixture.child_l);
    muxserverTunnelDownStreamResume(fixture.mux, fixture.child_l);
    twfRequire(! lineIsAlive(fixture.child_l), "server terminal drain left its owned child alive");
    twfRequireEqualU32(fixture.trace.next_payload, 2, "server retained pre-Close payload was not delivered once");
    twfRequireEqualU32(fixture.trace.next_payload_bytes,
                       kSibling + kFirst,
                       "server terminal drain delivered bytes after Close or lost pre-Close bytes");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "server terminal drain did not finish exactly once");
    twfRequireLineStateZeroed(fixture.child_l, fixture.mux, "server terminal child state survived ordered drain");
    for (uint32_t i = 0; i < kSibling; ++i)
    {
        twfRequire(fixture.capture[i] == 0x52, "the server sibling payload was reordered or corrupted");
    }
    for (uint32_t i = kSibling; i < kSibling + kFirst; ++i)
    {
        twfRequire(fixture.capture[i] == 0x31, "the server pre-Close payload was reordered or corrupted");
    }
    twfRequireOwnedLineReclaimed(fixture.child_l, "MuxServer same-batch peer Close");
    fixture.child_l = NULL;

    destroyServerSibling(&fixture, sibling_l);
    fixtureTeardown(&fixture);
}

static void caseDetachedConfiguration(void)
{
    twfSetCase("MuxServer detached backlog configuration follows RAM profile and validates overrides");

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
        cJSON *settings    = cJSON_Parse("{}");
        twfRequire(settings != NULL, "failed to create default MuxServer settings");
        node.node_settings_json = settings;

        tunnel_t *mux = muxserverTunnelCreate(&node);
        twfRequire(mux != NULL, "profile-derived detached MuxServer settings were rejected");
        muxserver_tstate_t *ts = tunnelGetState(mux);
        twfRequireEqualU32(
            ts->detached_buffer_limit, profiles[i].buffer_limit, "profile-derived MuxServer byte limit drifted");
        twfRequireEqualU32(
            ts->detached_child_limit, profiles[i].child_limit, "profile-derived MuxServer child limit drifted");
        twfRequireEqualU32(ts->child_buffer_resume_threshold,
                           kMuxDefaultChildBufferResumeThreshold,
                           "default MuxServer child resume threshold drifted");
        twfRequireEqualU32(
            ts->max_children, kMuxDefaultMaxChildrenPerParent, "default MuxServer per-parent child limit drifted");
        twfRequireEqualU32(
            ts->max_live_children, kMuxDefaultMaxLiveChildren, "default MuxServer aggregate child limit drifted");
        twfRequireEqualU32(
            ts->memory_reserve, profiles[i].buffer_limit, "profile-derived MuxServer admission reserve drifted");
        twfRequireEqualU32(ts->memory_fallback_max_live_children,
                           profiles[i].child_limit,
                           "profile-derived MuxServer fallback child ceiling drifted");
        twfRequireEqualU32(ts->initial_child_idle_timeout_ms,
                           kMuxDefaultInitialChildIdleTimeoutMs,
                           "default MuxServer initial child idle timeout drifted");
        twfRequireEqualU32(ts->active_child_idle_timeout_ms,
                           kMuxDefaultActiveChildIdleTimeoutMs,
                           "default MuxServer active child idle timeout drifted");
        muxserverTunnelDestroy(mux, wwLifecycleProcessShutdown());
        cJSON_Delete(settings);
    }

    GSTATE.ram_profile = kRamProfileL2Memory;
    cJSON *settings    = cJSON_Parse("{\"child-buffer-limit\":1000,\"child-buffer-resume-threshold\":2000,"
                                     "\"detached-buffer-limit\":0,\"detached-child-limit\":9}");
    twfRequire(settings != NULL, "failed to create explicit MuxServer settings");
    node.node_settings_json = settings;
    tunnel_t *mux           = muxserverTunnelCreate(&node);
    twfRequire(mux != NULL, "explicit detached MuxServer settings were rejected");
    muxserver_tstate_t *ts = tunnelGetState(mux);
    twfRequireEqualU32(ts->detached_buffer_limit, 0, "MuxServer zero byte limit was not preserved");
    twfRequireEqualU32(ts->detached_child_limit, 9, "MuxServer explicit child limit was not preserved");
    twfRequireEqualU32(
        ts->child_buffer_resume_threshold, 1000, "MuxServer child resume threshold was not capped to its buffer limit");
    muxserverTunnelDestroy(mux, wwLifecycleProcessShutdown());
    cJSON_Delete(settings);

    settings = cJSON_Parse("{\"detached-child-limit\":-1}");
    twfRequire(settings != NULL, "failed to create invalid MuxServer settings");
    node.node_settings_json = settings;
    twfRequire(muxserverTunnelCreate(&node) == NULL, "negative detached MuxServer child limit was accepted");
    cJSON_Delete(settings);

    settings = cJSON_Parse("{\"child-buffer-resume-threshold\":0}");
    twfRequire(settings != NULL, "failed to create invalid MuxServer resume-threshold settings");
    node.node_settings_json = settings;
    twfRequire(muxserverTunnelCreate(&node) == NULL, "zero MuxServer child resume threshold was accepted");
    cJSON_Delete(settings);

    settings = cJSON_Parse("{\"max-children\":11,\"max-live-children\":12,"
                           "\"memory-fallback-max-live-children\":7,\"memory-high-watermark-percent\":90,"
                           "\"memory-low-watermark-percent\":70,\"memory-reserve\":0,"
                           "\"initial-child-idle-timeout-ms\":20,\"active-child-idle-timeout-ms\":30}");
    twfRequire(settings != NULL, "failed to create explicit MuxServer admission settings");
    node.node_settings_json = settings;
    mux                     = muxserverTunnelCreate(&node);
    twfRequire(mux != NULL, "valid explicit MuxServer admission settings were rejected");
    ts = tunnelGetState(mux);
    twfRequireEqualU32(ts->max_children, 11, "MuxServer max-children override was not preserved");
    twfRequireEqualU32(ts->max_live_children, 12, "MuxServer max-live-children override was not preserved");
    twfRequireEqualU32(
        ts->memory_fallback_max_live_children, 7, "MuxServer fallback ceiling override was not preserved");
    twfRequireEqualU32(ts->memory_reserve, 0, "MuxServer zero memory reserve was not preserved");
    muxserverTunnelDestroy(mux, wwLifecycleProcessShutdown());
    cJSON_Delete(settings);

    static const char *const invalid_admission_settings[] = {
        "{\"max-children\":0}",
        "{\"max-children\":11,\"max-live-children\":10}",
        "{\"max-live-children\":10,\"memory-fallback-max-live-children\":11}",
        "{\"memory-high-watermark-percent\":75,\"memory-low-watermark-percent\":75}",
        "{\"memory-high-watermark-percent\":99,\"memory-low-watermark-percent\":100}",
        "{\"initial-child-idle-timeout-ms\":20,\"active-child-idle-timeout-ms\":19}",
        "{\"memory-reserve\":-1}",
        "{\"max-children\":1.5}",
    };
    for (size_t i = 0; i < ARRAY_SIZE(invalid_admission_settings); ++i)
    {
        settings = cJSON_Parse(invalid_admission_settings[i]);
        twfRequire(settings != NULL, "failed to create invalid MuxServer admission settings");
        node.node_settings_json = settings;
        twfRequire(muxserverTunnelCreate(&node) == NULL, "invalid MuxServer admission relationship was accepted");
        cJSON_Delete(settings);
    }

    GSTATE.ram_profile = previous_ram_profile;
}

int main(void)
{
    caseDownstreamFraming(kMuxMaxDataFrameLength, 1, "a payload exactly at the per-frame limit stays one frame");
    caseDownstreamFraming(kMuxMaxDataFrameLength + 1U, 2, "a payload one byte over the limit becomes two frames");
    caseDownstreamFraming((3U * kMuxMaxDataFrameLength) - 5U, 3, "a payload spanning three frames is fragmented");

    caseLargeCompleteBatchIsDrained();
    caseConfiguredResumeThresholdControlsFlowResume();
    casePerParentAdmissionRejectsWithClose();
    caseDuplicateOpenClosesParent();
    caseChildIdlePromotionAndImmediateRemoval();
    casePeerCloseDropsLateFramesAndKeepsSiblingProgress();
    caseDetachedConfiguration();

    printf("muxserver_frame_encoding_test: all cases passed\n");
    return 0;
}
