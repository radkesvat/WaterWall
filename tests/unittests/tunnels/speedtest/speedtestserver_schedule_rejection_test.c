/*
 * Covers: SpeedTestServer scheduling, fragmented splice input and optional payload verification;
 * define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: schedule refusals, mixed ordinary/pipe fragments, coalesced frames, UDP verification modes,
 * malformed lengths and borrowed-line cleanup.
 * Checks: Assertion labels include: SpeedTestServer scheduled Report after Send refusal closed the line;
 * SpeedTestServer finished an unexpected borrowed line; SpeedTestServer Hello exceeded test buffer; Send
 * refusal did not close the borrowed server line
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.speedtestserver_schedule_rejection_unit
 */
/* A rejected Send admission must stop Hello handling before Report scheduling. */

#include "SpeedTestServer/structure.h"

#include "fixtures/failure/tunnel_line_failure_harness.h"

enum
{
    kSpeedServerTestBufferSize = 4096,
    kSpeedServerTestPayloadSize = 256,
    kSpeedServerTestFrameSize   = kSpeedTestServerFrameHeaderSize + kSpeedServerTestPayloadSize,
};

typedef struct speedtestserver_fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  line_pool;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *speed;
    line_t          *line;
} speedtestserver_fixture_t;

static speedtestserver_fixture_t *g_fixture;
static bool                       g_refuse_next_line_task;
static bool                       g_refuse_next_delayed_task;
static bool                       g_forbid_delayed_task;
static unsigned int               g_delayed_task_submissions;

line_task_submit_result_e __real_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel);
line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel);
line_task_submit_result_e __real_lineScheduleDelayedTask(line_t *const line, LineTaskFnNoBuf task, uint32_t delay_ms,
                                                         tunnel_t *t, LineTaskCancelFn on_cancel);
line_task_submit_result_e __wrap_lineScheduleDelayedTask(line_t *const line, LineTaskFnNoBuf task, uint32_t delay_ms,
                                                         tunnel_t *t, LineTaskCancelFn on_cancel);

line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel)
{
    if (! g_refuse_next_line_task)
    {
        return __real_lineScheduleTask(line, task, t, on_cancel);
    }

    g_refuse_next_line_task = false;
    lineRef(line);
    if (on_cancel != NULL)
    {
        on_cancel(t, line, kLineTaskCancelEnqueueFailure);
    }
    lineUnref(line);
    return kLineTaskSubmitRejectedSettled;
}

line_task_submit_result_e __wrap_lineScheduleDelayedTask(line_t *const line, LineTaskFnNoBuf task, uint32_t delay_ms,
                                                         tunnel_t *t, LineTaskCancelFn on_cancel)
{
    g_delayed_task_submissions += 1U;
    if (g_refuse_next_delayed_task)
    {
        g_refuse_next_delayed_task = false;
        lineRef(line);
        if (on_cancel != NULL)
        {
            on_cancel(t, line, kLineTaskCancelResourceFailure);
        }
        lineUnref(line);
        return kLineTaskSubmitRejectedSettled;
    }

    twfRequire(! g_forbid_delayed_task, "SpeedTestServer scheduled Report after Send refusal closed the line");
    return __real_lineScheduleDelayedTask(line, task, delay_ms, t, on_cancel);
}

static void ownerFinish(tunnel_t *prev, line_t *line)
{
    speedtestserver_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL && prev == fixture->prev && line == fixture->line,
               "SpeedTestServer finished an unexpected borrowed line");
    ++fixture->trace.prev_finish;
    twfRecord(&fixture->trace, 'f');
    lineDestroy(line);
}

static void fixtureSetup(speedtestserver_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetup(&fixture->env, kSpeedServerTestBufferSize, 0);

    fixture->prev  = twfCreatePrevTunnel(&fixture->trace);
    fixture->speed = tunnelCreate(NULL, sizeof(speedtestserver_tstate_t), sizeof(speedtestserver_lstate_t));
    twfRequire(fixture->speed != NULL, "failed to create SpeedTestServer fixture tunnel");
    tunnelBind(fixture->prev, fixture->speed);
    fixture->prev->fnFinD = ownerFinish;

    speedtestserver_tstate_t *state = tunnelGetState(fixture->speed);
    state->report_interval_ms       = 1000;
    state->quiet                    = true;
    mutexInit(&state->aggregate_mutex);

    twfLinePoolSetup(&fixture->line_pool, fixture->speed->lstate_size, 4);
    fixture->line = twfLinePoolCreateLine(&fixture->line_pool);
    speedtestserverLinestateInitialize(lineGetState(fixture->line, fixture->speed), fixture->speed, fixture->line);
    g_fixture = fixture;
}

static sbuf_t *makeDownloadHello(speedtestserver_fixture_t *fixture)
{
    const uint32_t frame_size = kSpeedTestServerFrameHeaderSize + kSpeedTestServerHelloSize;
    sbuf_t        *buf        = bufferpoolGetSmallBuffer(fixture->env.pool);
    twfRequire(sbufGetMaximumWriteableSize(buf) >= frame_size, "SpeedTestServer Hello exceeded test buffer");
    sbufSetLength(buf, frame_size);

    uint8_t *frame = sbufGetMutablePtr(buf);
    speedtestserverWriteHeader(frame,
                               kSpeedTestServerFrameHello,
                               kSpeedTestServerFlagDownload | kSpeedTestServerFlagTcp,
                               7,
                               kSpeedTestServerHelloSize,
                               0,
                               0,
                               0,
                               0);

    uint8_t *hello = frame + kSpeedTestServerFrameHeaderSize;
    PUT_BE32(hello + 0, 1000);
    PUT_BE32(hello + 4, 0);
    PUT_BE32(hello + 8, 1000);
    PUT_BE32(hello + 12, 256);
    PUT_BE64(hello + 16, 0);
    PUT_BE32(hello + 24, 1);
    PUT_BE32(hello + 28, 7);
    return buf;
}

static void fixtureTeardownAfterClose(speedtestserver_fixture_t *fixture)
{
    speedtestserver_tstate_t *state = tunnelGetState(fixture->speed);
    mutexDestroy(&state->aggregate_mutex);
    twfRequireEqualU32((uint32_t) masterpoolGetCheckedOut(fixture->line_pool.master),
                       0,
                       "SpeedTestServer fixture retained its borrowed line");
    twfLinePoolTeardown(&fixture->line_pool);
    tunnelDestroy(fixture->speed);
    tunnelDestroy(fixture->prev);
    g_fixture = NULL;
    twfWorkerEnvTeardown(&fixture->env);
}

static void caseHelloStopsAfterSendAdmissionClosesLine(void)
{
    twfSetCase("SpeedTestServer Hello stops after Send admission closes the line");
    speedtestserver_fixture_t fixture;
    fixtureSetup(&fixture);

    lineRef(fixture.line);
    g_refuse_next_line_task = true;
    g_forbid_delayed_task   = true;
    speedtestserverTunnelUpStreamPayload(fixture.speed, fixture.line, makeDownloadHello(&fixture));
    g_forbid_delayed_task = false;

    twfRequire(! lineIsAlive(fixture.line), "Send refusal did not close the borrowed server line");
    twfRequireLineStateZeroed(fixture.line, fixture.speed, "Send refusal left SpeedTestServer line state alive");
    twfRequireEqualU32(fixture.trace.prev_payload, 2, "Hello refusal did not emit exactly ACK plus Error");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "Hello refusal did not emit one downstream Finish");
    twfRequireEqualU32(twfLineRefCount(fixture.line), 1, "Hello refusal leaked a physical line reference");
    twfRequireNoLeakedBuffers();

    lineUnref(fixture.line);
    fixture.line = NULL;
    fixtureTeardownAfterClose(&fixture);
}

static void caseReportRejectionFinishesRealOwner(void)
{
    twfSetCase("SpeedTestServer report rejection finishes the real owner");
    speedtestserver_fixture_t fixture;
    fixtureSetup(&fixture);

    speedtestserver_lstate_t *ls = lineGetState(fixture.line, fixture.speed);
    ls->report_interval_ms       = 1000;

    lineRef(fixture.line);
    g_delayed_task_submissions = 0;
    g_refuse_next_delayed_task = true;
    speedtestserverScheduleReport(fixture.speed, fixture.line, ls);

    twfRequire(! lineIsAlive(fixture.line), "report refusal left the borrowed speed-test line alive");
    twfRequireLineStateZeroed(fixture.line, fixture.speed, "report refusal retained its latch or line state");
    twfRequireEqualU32(fixture.trace.prev_payload, 1, "report refusal did not send exactly one Error frame");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "report refusal did not Finish the real owner once");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "report refusal reflected Finish away from the owner");
    twfRequireEqualU32(g_delayed_task_submissions, 1, "report refusal armed a second report");
    twfRequireNoLeakedBuffers();

    lineUnref(fixture.line);
    fixture.line = NULL;
    fixtureTeardownAfterClose(&fixture);
}

static speedtestserver_lstate_t *fixturePrepareReceiver(speedtestserver_fixture_t *fixture, bool verify, bool udp)
{
    speedtestserver_lstate_t *ls = lineGetState(fixture->line, fixture->speed);
    ls->hello_received           = true;
    ls->upload                   = true;
    ls->receiver_finished        = false;
    ls->payload_size             = kSpeedServerTestPayloadSize;
    ls->stream_id                = 7;
    ls->verify_payload           = verify;
    ls->mode                     = udp ? kSpeedTestServerModeUdp : kSpeedTestServerModeTcp;
    return ls;
}

static sbuf_t *makeInputBytes(speedtestserver_fixture_t *fixture, const uint8_t *bytes, uint32_t length, bool pipe_body)
{
    if (pipe_body)
    {
#if WW_HAVE_SPLICE
        sbuf_t *buf = bufferpoolGetSpliceBuffer(fixture->env.pool);
        twfRequire(buf != NULL && length <= kSpeedServerTestBufferSize, "invalid SpeedTestServer pipe fixture");
        twfRequire(write(sbufSpliceMetadata(buf).pipefd[1], bytes, length) == (ssize_t) length,
                   "failed to populate SpeedTestServer pipe fragment");
        buf->capacity = buf->l_pad + length;
        sbufSetLength(buf, length);
        return buf;
#else
        twfRequire(false, "pipe fixture requested without splice support");
#endif
    }

    sbuf_t *buf = bufferpoolGetSmallBuffer(fixture->env.pool);
    twfRequire(length <= sbufGetMaximumWriteableSize(buf), "SpeedTestServer ordinary fixture is too large");
    memoryCopy(sbufGetMutablePtr(buf), bytes, length);
    sbufSetLength(buf, length);
    return buf;
}

static void makeDataBytes(uint8_t *bytes, uint64_t sequence, bool udp, bool corrupt)
{
    const uint16_t flags = kSpeedTestServerFlagUpload | (udp ? kSpeedTestServerFlagUdp : kSpeedTestServerFlagTcp);
    speedtestserverWriteHeader(
        bytes, kSpeedTestServerFrameData, flags, 7, kSpeedServerTestPayloadSize, sequence, 0, 0, 0);
    speedtestserverFillPattern(
        bytes + kSpeedTestServerFrameHeaderSize, kSpeedServerTestPayloadSize, 7, sequence, flags);
    if (corrupt)
    {
        bytes[kSpeedTestServerFrameHeaderSize + 17] ^= 0xFF;
    }
}

static void fixtureCloseReceiver(speedtestserver_fixture_t *fixture)
{
    speedtestserverTunnelUpStreamFinish(fixture->speed, fixture->line);
    twfRequireLineStateZeroed(fixture->line, fixture->speed, "receive cleanup retained SpeedTestServer state");
    lineDestroy(fixture->line);
    fixture->line = NULL;
    fixtureTeardownAfterClose(fixture);
}

static void requireReceivedPair(const speedtestserver_lstate_t *ls, bool verify)
{
    twfRequire(ls->receiver.bytes == 2U * kSpeedServerTestPayloadSize && ls->receiver.packets == 2,
               "SpeedTestServer did not count both DATA frames exactly once");
    twfRequire(ls->receiver.valid_packets == (verify ? 1U : 0U),
               "SpeedTestServer reported verification without checking the payload");
    twfRequire(ls->receiver.validation_errors == (verify ? 1U : 0U),
               "SpeedTestServer corruption accounting did not follow the verification setting");
    twfRequire(ls->receiver.lost_packets == 0 && ls->receiver.duplicate_packets == 0 && ls->expected_recv_sequence == 2,
               "SpeedTestServer lost frame order while consuming DATA");
    twfRequire(splicestreamLength(ls->recv_stream) == 0 && splicestreamCharge(ls->recv_stream) == 0,
               "SpeedTestServer retained bytes after complete frames");
    twfRequireNoLeakedBuffers();
}

#if WW_HAVE_SPLICE
static void caseFragmentedSpliceReceive(bool verify)
{
    twfSetCase(verify ? "SpeedTestServer verifies fragmented splice frames"
                      : "SpeedTestServer discards unverified fragmented splice frames");
    speedtestserver_fixture_t fixture;
    fixtureSetup(&fixture);
    speedtestserver_lstate_t *ls = fixturePrepareReceiver(&fixture, verify, false);
    uint8_t                   frames[2 * kSpeedServerTestFrameSize];
    makeDataBytes(frames, 0, false, false);
    makeDataBytes(frames + kSpeedServerTestFrameSize, 1, false, true);

    speedtestserverTunnelUpStreamPayload(fixture.speed, fixture.line, makeInputBytes(&fixture, frames, 13, true));
    twfRequire(ls->receiver.packets == 0 && splicestreamLength(ls->recv_stream) == 13,
               "SpeedTestServer did not retain its incomplete splice header");

    const uint32_t partial_length = kSpeedTestServerFrameHeaderSize + 17;
    speedtestserverTunnelUpStreamPayload(
        fixture.speed, fixture.line, makeInputBytes(&fixture, frames + 13, partial_length - 13, false));
    twfRequire(ls->receiver.packets == 0 && splicestreamBodyBytes(ls->recv_stream) == 17,
               "SpeedTestServer consumed an incomplete DATA body");

    speedtestserverTunnelUpStreamPayload(
        fixture.speed,
        fixture.line,
        makeInputBytes(&fixture, frames + partial_length, (uint32_t) sizeof(frames) - partial_length, true));
    requireReceivedPair(ls, verify);
    fixtureCloseReceiver(&fixture);
}
#endif

static void caseOrdinaryUdpReceive(bool verify)
{
    twfSetCase(verify ? "SpeedTestServer verifies ordinary UDP frames"
                      : "SpeedTestServer accepts unverified ordinary UDP frames");
    speedtestserver_fixture_t fixture;
    fixtureSetup(&fixture);
    speedtestserver_lstate_t *ls = fixturePrepareReceiver(&fixture, verify, true);
    uint8_t                   frame[kSpeedServerTestFrameSize];
    makeDataBytes(frame, 0, true, false);
    speedtestserverTunnelUpStreamPayload(
        fixture.speed, fixture.line, makeInputBytes(&fixture, frame, sizeof(frame), false));
    makeDataBytes(frame, 1, true, true);
    speedtestserverTunnelUpStreamPayload(
        fixture.speed, fixture.line, makeInputBytes(&fixture, frame, sizeof(frame), false));
    requireReceivedPair(ls, verify);
    fixtureCloseReceiver(&fixture);
}

static void caseMalformedFrameLength(bool pipe_body)
{
    twfSetCase(pipe_body ? "SpeedTestServer rejects oversized splice DATA length"
                         : "SpeedTestServer rejects oversized ordinary DATA length");
    speedtestserver_fixture_t fixture;
    fixtureSetup(&fixture);
    discard fixturePrepareReceiver(&fixture, false, false);
    uint8_t header[kSpeedTestServerFrameHeaderSize];
    speedtestserverWriteHeader(header,
                               kSpeedTestServerFrameData,
                               kSpeedTestServerFlagUpload | kSpeedTestServerFlagTcp,
                               7,
                               kSpeedServerTestPayloadSize + 1,
                               0,
                               0,
                               0,
                               0);

    lineRef(fixture.line);
    speedtestserverTunnelUpStreamPayload(
        fixture.speed, fixture.line, makeInputBytes(&fixture, header, sizeof(header), pipe_body));
    twfRequire(! lineIsAlive(fixture.line), "oversized DATA length did not close the borrowed line");
    twfRequireLineStateZeroed(fixture.line, fixture.speed, "oversized DATA length retained receive state");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "oversized DATA length did not Finish the real owner once");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "oversized DATA length reflected Finish away from the owner");
    twfRequireEqualU32(twfLineRefCount(fixture.line), 1, "oversized DATA length leaked a line reference");
    twfRequireNoLeakedBuffers();
    lineUnref(fixture.line);
    fixture.line = NULL;
    fixtureTeardownAfterClose(&fixture);
}

int main(void)
{
    caseHelloStopsAfterSendAdmissionClosesLine();
    caseReportRejectionFinishesRealOwner();
    caseOrdinaryUdpReceive(false);
    caseOrdinaryUdpReceive(true);
    caseMalformedFrameLength(false);
#if WW_HAVE_SPLICE
    caseFragmentedSpliceReceive(false);
    caseFragmentedSpliceReceive(true);
    caseMalformedFrameLength(true);
#endif
    puts("speedtestserver_schedule_rejection_test: all cases passed");
    return 0;
}
