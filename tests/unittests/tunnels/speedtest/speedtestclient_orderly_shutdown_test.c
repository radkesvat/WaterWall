/*
 * Covers: speedtestclient orderly shutdown; the explicit inputs, callbacks and expected results below
 * define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseWorkerStopDrainsOnlyItsPublishedSlots, caseRequiredStartupFailuresPropagateStartupStatus,
 * caseAcceptedQueuedTimerAdmissionClosureUsesCleanup, caseEstStopsAfterSendAdmissionClosesLine,
 * caseReportRejectionClosesOwnedLine, caseAcceptedReportCancellationLeavesOwnerDrainSafe,
 * caseFragmentedReceiverFrames, caseDatagramReceiverVerification, caseMalformedReceiverLengthClosesLine
 * Checks: Assertion labels include: SpeedTestClient teardown found a live owner slot; worker 0 did not
 * clear its slot before close; worker 0 drained another worker's slot; a line that never published Init
 * emitted Finish; fragmented ordinary/private-pipe frames preserve boundaries and statistics; payload
 * checking is optional while malformed protocol lengths still close the owned line
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.speedtestclient_orderly_shutdown_test_unit
 */
#include "SpeedTestClient/structure.h"
#include "fixtures/splice_inventory.h"

#include "ev_memory.h"
#include "fixtures/failure/tunnel_orderly_shutdown_harness.h"
#include "startup.h"

enum
{
    kTestWorkers       = 2,
    kTestLinePoolItems = 4,
    kTestBufferSize    = 4096
};

typedef struct speedtestclient_fixture_s
{
    tos_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *speed;
    tunnel_t        *next;
    tunnel_chain_t  *chain;
    master_pool_t   *line_master;
    line_t          *lines[kTestWorkers];
} speedtestclient_fixture_t;

static bool         fail_next_line_task;
static bool         fail_next_delayed_line_task;
static unsigned int delayed_line_task_submissions;
static bool         track_next_allocation;
static void        *tracked_allocation;
static size_t       tracked_free_count;

void                     *__real_memoryAllocate(size_t size);
void                     *__wrap_memoryAllocate(size_t size);
void                      __real_memoryFree(void *ptr);
void                      __wrap_memoryFree(void *ptr);
line_task_submit_result_e __real_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel);
line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel);
line_task_submit_result_e __real_lineScheduleDelayedTask(line_t *const line, LineTaskFnNoBuf task, uint32_t delay_ms,
                                                         tunnel_t *t, LineTaskCancelFn on_cancel);
line_task_submit_result_e __wrap_lineScheduleDelayedTask(line_t *const line, LineTaskFnNoBuf task, uint32_t delay_ms,
                                                         tunnel_t *t, LineTaskCancelFn on_cancel);

void *__wrap_memoryAllocate(size_t size)
{
    void *allocation = __real_memoryAllocate(size);
    if (track_next_allocation)
    {
        track_next_allocation = false;
        tracked_allocation    = allocation;
    }
    return allocation;
}

void __wrap_memoryFree(void *ptr)
{
    if (ptr != NULL && ptr == tracked_allocation)
    {
        tracked_free_count++;
    }
    __real_memoryFree(ptr);
}

line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel)
{
    if (! fail_next_line_task)
    {
        return __real_lineScheduleTask(line, task, t, on_cancel);
    }

    fail_next_line_task = false;
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
    delayed_line_task_submissions += 1U;
    if (! fail_next_delayed_line_task)
    {
        return __real_lineScheduleDelayedTask(line, task, delay_ms, t, on_cancel);
    }

    fail_next_delayed_line_task = false;
    lineRef(line);
    if (on_cancel != NULL)
    {
        on_cancel(t, line, kLineTaskCancelAdmissionClosed);
    }
    lineUnref(line);
    return kLineTaskSubmitRejectedSettled;
}

static void fixtureSetup(speedtestclient_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    tosWorkerEnvSetup(&fixture->env, kTestWorkers, kTestBufferSize, kTestBufferSize);

    fixture->speed = tunnelCreate(NULL, sizeof(speedtestclient_tstate_t), sizeof(speedtestclient_lstate_t));
    twfRequire(fixture->speed != NULL, "failed to create SpeedTestClient fixture tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    tunnelBind(fixture->speed, fixture->next);

    fixture->chain = memoryAllocateZero(sizeof(*fixture->chain) + kTestWorkers * sizeof(generic_pool_t *));
    twfRequire(fixture->chain != NULL, "failed to allocate SpeedTestClient fixture chain");
    fixture->chain->workers_count = kTestWorkers;
    fixture->speed->chain         = fixture->chain;
    fixture->next->chain          = fixture->chain;

    fixture->line_master = masterpoolCreateWithCapacity(2 * kTestWorkers * kTestLinePoolItems);
    twfRequire(fixture->line_master != NULL, "failed to create SpeedTestClient line master pool");
    fixture->chain->masterpool_line_pool = fixture->line_master;
    for (wid_t wid = 0; wid < kTestWorkers; ++wid)
    {
        fixture->chain->line_pools[wid] = genericpoolCreateWithDefaultCacheAlignedAllocatorAndCapacity(
            fixture->line_master, sizeof(line_t) + fixture->speed->lstate_size, kTestLinePoolItems);
        twfRequire(fixture->chain->line_pools[wid] != NULL, "failed to create SpeedTestClient worker line pool");
    }

    speedtestclient_tstate_t *state = tunnelGetState(fixture->speed);
    state->connection_count         = kTestWorkers;
    state->start_delay_ms           = 1;
    state->owned_lines              = memoryAllocateZero(kTestWorkers * sizeof(*state->owned_lines));
    twfRequire(state->owned_lines != NULL, "failed to allocate SpeedTestClient owner inventory");
    atomic_init(&state->stopping, false);
    mutexInit(&state->aggregate_mutex);
}

static line_t *publishLine(speedtestclient_fixture_t *fixture, uint32_t stream_id, bool init_sent)
{
    const wid_t wid      = (wid_t) (stream_id % kTestWorkers);
    const wid_t previous = tosSetCurrentWorker(wid);
    line_t     *line     = lineCreateForWorker(wid, fixture->chain->line_pools, wid);
    discard     tosSetCurrentWorker(previous);
    twfRequire(line != NULL, "failed to create SpeedTestClient owned line");

    speedtestclient_lstate_t *line_state = lineGetState(line, fixture->speed);
    speedtestclientLinestateInitialize(line_state, fixture->speed, line, stream_id);
    line_state->upstream_init_sent  = init_sent;
    speedtestclient_tstate_t *state = tunnelGetState(fixture->speed);
    twfRequire(state->owned_lines[stream_id] == NULL, "SpeedTestClient fixture slot was already occupied");
    state->owned_lines[stream_id] = line;
    fixture->lines[stream_id]     = line;
    return line;
}

static void drainWorker(speedtestclient_fixture_t *fixture, wid_t wid)
{
    const wid_t previous = tosSetCurrentWorker(wid);
    speedtestclientTunnelOnWorkerStop(fixture->speed, wid, wwLifecycleProcessShutdown());
    discard tosSetCurrentWorker(previous);
}

static void fixtureTeardown(speedtestclient_fixture_t *fixture)
{
    speedtestclient_tstate_t *state = tunnelGetState(fixture->speed);
    for (uint32_t stream_id = 0; stream_id < state->connection_count; ++stream_id)
    {
        twfRequire(state->owned_lines[stream_id] == NULL, "SpeedTestClient teardown found a live owner slot");
    }
    memoryFree(state->owned_lines);
    state->owned_lines = NULL;
    mutexDestroy(&state->aggregate_mutex);
    for (wid_t wid = 0; wid < kTestWorkers; ++wid)
    {
        genericpoolDestroy(fixture->chain->line_pools[wid]);
    }
    masterpoolDestroy(fixture->line_master);
    memoryFree(fixture->chain);
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->speed);
    tosWorkerEnvTeardown(&fixture->env);
}

static void caseWorkerStopDrainsOnlyItsPublishedSlots(void)
{
    twfSetCase("SpeedTestClient worker stop drains its authoritative slots");
    tosResetProcessApi(true);
    speedtestclient_fixture_t fixture;
    fixtureSetup(&fixture);

    publishLine(&fixture, 0, false);
    publishLine(&fixture, 1, true);
    speedtestclient_tstate_t *state = tunnelGetState(fixture.speed);

    drainWorker(&fixture, 0);
    twfRequire(state->owned_lines[0] == NULL, "worker 0 did not clear its slot before close");
    twfRequire(state->owned_lines[1] == fixture.lines[1], "worker 0 drained another worker's slot");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "a line that never published Init emitted Finish");

    drainWorker(&fixture, 0);
    twfRequireEqualU32(fixture.trace.next_finish, 0, "repeated worker stop reclosed an empty slot");

    drainWorker(&fixture, 1);
    twfRequire(state->owned_lines[1] == NULL, "worker 1 did not clear its slot before close");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "an initialized line did not emit exactly one Finish");
    drainWorker(&fixture, 1);
    twfRequireEqualU32(fixture.trace.next_finish, 1, "repeated worker stop emitted another Finish");
    twfRequireEqualU32(masterpoolGetCheckedOut(fixture.line_master), 0, "worker stop retained an owned line");
    tosRequireNoProcessApiCall();

    fixtureTeardown(&fixture);
}

static void caseRequiredStartupFailuresPropagateStartupStatus(void)
{
    twfSetCase("SpeedTestClient required startup failures propagate startup status");
    speedtestclient_fixture_t fixture;
    fixtureSetup(&fixture);

    speedtestclient_tstate_t *state = tunnelGetState(fixture.speed);
    state->connection_count         = 1;

    tosResetProcessApi(true);
    workerMessagesCloseAdmission(getWorker(0));
    track_next_allocation        = true;
    tracked_allocation           = NULL;
    tracked_free_count           = 0;
    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    speedtestclientTunnelOnStart(fixture.speed);
    twfRequire(! wwStartupSucceeded(wwStartupContextEnd(&startup)), "required task refusal reported startup success");
    twfRequire(tracked_allocation != NULL && tracked_free_count == 1,
               "direct delayed-task refusal did not release the retained stream id exactly once");
    tosRequireNoProcessApiCall();

    fixtureTeardown(&fixture);
}

static void caseAcceptedQueuedTimerAdmissionClosureUsesCleanup(void)
{
    twfSetCase("SpeedTestClient accepted queued timer admission closure uses cleanup");
    tosResetProcessApi(true);
    speedtestclient_fixture_t fixture;
    fixtureSetup(&fixture);

    speedtestclient_tstate_t *state = tunnelGetState(fixture.speed);
    state->connection_count         = 1;
    const wid_t previous_wid        = tosSetCurrentWorker(1);
    track_next_allocation           = true;
    tracked_allocation              = NULL;
    tracked_free_count              = 0;

    ww_startup_context_t startup = {0};
    wwStartupContextBegin(&startup);
    speedtestclientTunnelOnStart(fixture.speed);
    twfRequire(wwStartupSucceeded(wwStartupContextEnd(&startup)), "accepted timer setup reported startup failure");
    twfRequire(tracked_allocation != NULL && tracked_free_count == 0,
               "accepted queued setup released its payload before settlement");

    workerMessagesCloseAdmission(getWorker(0));
    tosPumpWorker(&fixture.env, 0);
    twfRequireEqualU32((uint32_t) tracked_free_count, 1, "accepted setup cleanup did not release the stream id once");
    tosRequireNoProcessApiCall();

    discard tosSetCurrentWorker(previous_wid);
    fixtureTeardown(&fixture);
}

static void caseEstStopsAfterSendAdmissionClosesLine(void)
{
    twfSetCase("SpeedTestClient Est stops after send admission closes the line");
    tosResetProcessApi(true);
    speedtestclient_fixture_t fixture;
    fixtureSetup(&fixture);

    speedtestclient_tstate_t *state = tunnelGetState(fixture.speed);
    state->connection_count         = 1;
    state->upload                   = true;
    state->report_interval_ms       = 1000;
    line_t *line                    = publishLine(&fixture, 0, true);

    const wid_t previous_wid = tosSetCurrentWorker(0);
    lineRef(line);
    fail_next_line_task = true;
    speedtestclientTunnelDownStreamEst(fixture.speed, line);

    twfRequire(! lineIsAlive(line), "send admission refusal did not close the owned speed-test line");
    twfRequire(state->owned_lines[0] == NULL, "send admission refusal left the owned line published");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "send admission refusal did not emit one upstream Finish");
    twfRequireEqualU32(
        (uint32_t) fixture.env.loops[0]->ntimers, 0, "Est scheduled a report after send refusal destroyed the line");
    lineUnref(line);
    twfRequireEqualU32(masterpoolGetCheckedOut(fixture.line_master), 0, "Est retained the closed speed-test line");
    discard tosSetCurrentWorker(previous_wid);
    tosRequireNoProcessApiCall();

    fixtureTeardown(&fixture);
}

static void caseReportRejectionClosesOwnedLine(void)
{
    twfSetCase("SpeedTestClient report rejection closes the owned line");
    tosResetProcessApi(true);
    speedtestclient_fixture_t fixture;
    fixtureSetup(&fixture);

    speedtestclient_tstate_t *state = tunnelGetState(fixture.speed);
    state->connection_count         = 1;
    state->report_interval_ms       = 1000;
    line_t *line                    = publishLine(&fixture, 0, true);

    lineRef(line);
    delayed_line_task_submissions = 0;
    fail_next_delayed_line_task   = true;
    speedtestclientScheduleReport(fixture.speed, line, lineGetState(line, fixture.speed));

    twfRequire(! lineIsAlive(line), "report refusal left the owned speed-test line alive");
    twfRequire(state->owned_lines[0] == NULL, "report refusal left the owned line published");
    twfRequireLineStateZeroed(line, fixture.speed, "report refusal retained its latch or line state");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "report refusal did not emit one upstream Finish");
    twfRequireEqualU32(delayed_line_task_submissions, 1, "report refusal armed a second report");

    lineUnref(line);
    twfRequireEqualU32(masterpoolGetCheckedOut(fixture.line_master), 0, "report refusal retained the owned line");
    tosRequireNoProcessApiCall();
    fixtureTeardown(&fixture);
}

static void caseAcceptedReportCancellationLeavesOwnerDrainSafe(void)
{
    twfSetCase("SpeedTestClient accepted report cancellation leaves owner drain safe");
    tosResetProcessApi(true);
    speedtestclient_fixture_t fixture;
    fixtureSetup(&fixture);

    speedtestclient_tstate_t *state = tunnelGetState(fixture.speed);
    state->connection_count         = 1;
    state->report_interval_ms       = 60000;
    line_t *line                    = publishLine(&fixture, 0, true);

    delayed_line_task_submissions = 0;
    speedtestclientScheduleReport(fixture.speed, line, lineGetState(line, fixture.speed));
    twfRequireEqualU32(delayed_line_task_submissions, 1, "accepted report used the wrong number of submissions");
    twfRequireEqualU32((uint32_t) fixture.env.loops[0]->ntimers, 1, "accepted report did not arm its timer");

    workerMessagesCleanupPending(&fixture.env.workers[0]);
    twfRequireEqualU32((uint32_t) fixture.env.loops[0]->ntimers, 0, "quiescence did not cancel the accepted report");
    drainWorker(&fixture, 0);

    twfRequire(state->owned_lines[0] == NULL, "owner drain left the canceled-report line published");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "owner drain did not finish the initialized line once");
    twfRequireEqualU32(
        masterpoolGetCheckedOut(fixture.line_master), 0, "owner drain retained the canceled-report line");
    tosRequireNoProcessApiCall();
    fixtureTeardown(&fixture);
}

static line_t *prepareReceiver(speedtestclient_fixture_t *fixture, bool verify_payload, uint8_t mode)
{
    tosResetProcessApi(true);
    fixtureSetup(fixture);
    speedtestclient_tstate_t *state = tunnelGetState(fixture->speed);
    state->connection_count         = 1;
    state->duration_ms              = 1000;
    state->payload_size             = 256;
    state->mode                     = mode;
    state->download                 = true;
    state->verify_payload           = verify_payload;
    state->terminate_on_complete    = false;
    return publishLine(fixture, 0, true);
}

static sbuf_t *receiverInput(line_t *line, const uint8_t *bytes, uint32_t length, bool splice)
{
    twfRequire(length <= kTestBufferSize, "receiver fixture input exceeds one small pipe write");
    buffer_pool_t *pool = lineGetBufferPool(line);
#if WW_HAVE_SPLICE
    if (splice)
    {
        sbuf_t *buf = bufferpoolGetSpliceBuffer(pool);
        twfRequire(buf != NULL, "failed to create receiver fixture private pipe");
        twfRequire(write(sbufSpliceMetadata(buf).pipefd[1], bytes, length) == (ssize_t) length,
                   "failed to populate receiver fixture private pipe");
        buf->capacity = buf->l_pad + length;
        sbufSetLength(buf, length);
        return buf;
    }
#else
    twfRequire(! splice, "splice receiver fixture selected on an unsupported build");
#endif
    sbuf_t *buf = bufferpoolGetLargeBuffer(pool);
    memoryCopy(sbufGetMutablePtr(buf), bytes, length);
    sbufSetLength(buf, length);
    return buf;
}

static uint32_t receiverDataFrame(uint8_t *bytes, uint32_t length, uint64_t sequence, bool correct_pattern,
                                  uint8_t mode)
{
    const uint16_t flags = kSpeedTestClientFlagDownload |
                           (mode == kSpeedTestClientModeUdp ? kSpeedTestClientFlagUdp : kSpeedTestClientFlagTcp);
    speedtestclientWriteHeader(bytes, kSpeedTestClientFrameData, flags, 0, length, sequence, 0, 0, 0);
    speedtestclientFillPattern(bytes + kSpeedTestClientFrameHeaderSize, length, 0, sequence, flags);
    if (! correct_pattern)
    {
        bytes[kSpeedTestClientFrameHeaderSize] ^= 0x80U;
    }
    return kSpeedTestClientFrameHeaderSize + length;
}

static void requireReceiverStats(speedtestclient_lstate_t *ls, bool verify_payload)
{
    twfRequire(ls->receiver.bytes == 54 && ls->receiver.packets == 2,
               "receiver did not count both complete DATA frames exactly once");
    twfRequire(ls->receiver.valid_packets == (verify_payload ? 1U : 0U),
               "receiver claimed unchecked or corrupt payload was verified");
    twfRequire(ls->receiver.validation_errors == (verify_payload ? 1U : 0U),
               "receiver did not honor the configured payload verification policy");
    twfRequire(ls->expected_recv_sequence == 2 && ls->receiver.lost_packets == 0 && ls->receiver.duplicate_packets == 0,
               "receiver changed sequence accounting while consuming frame bodies");
}

static void caseFragmentedReceiverFrames(bool verify_payload, bool splice)
{
    twfSetCase(splice ? "SpeedTestClient mixed ordinary/private-pipe receive frames"
                      : "SpeedTestClient fragmented ordinary receive frames");
    speedtestclient_fixture_t fixture;
    line_t                   *line = prepareReceiver(&fixture, verify_payload, kSpeedTestClientModeTcp);
    speedtestclient_lstate_t *ls   = lineGetState(line, fixture.speed);
    uint8_t                   wire[2 * kSpeedTestClientFrameHeaderSize + 54];
    uint32_t                  first = receiverDataFrame(wire, 23, 0, true, kSpeedTestClientModeTcp);
    uint32_t                  total = first + receiverDataFrame(wire + first, 31, 1, false, kSpeedTestClientModeTcp);

    speedtestclientProcessIncoming(fixture.speed, line, receiverInput(line, wire, 7, false));
    twfRequire(lineIsAlive(line) && ls->receiver.packets == 0,
               "an incomplete DATA header closed the line or counted a packet");
    const uint32_t partial = kSpeedTestClientFrameHeaderSize + 12;
    speedtestclientProcessIncoming(fixture.speed, line, receiverInput(line, wire + 7, partial - 7, splice));
    twfRequire(lineIsAlive(line) && ls->receiver.packets == 0,
               "an incomplete DATA body closed the line or counted a packet");

    /* This delivery completes frame one and contains all of frame two. Header
     * cache refill must not change the first frame's decoded metadata. */
    speedtestclientProcessIncoming(fixture.speed, line, receiverInput(line, wire + partial, total - partial, splice));
    twfRequire(lineIsAlive(line), "DATA reception unexpectedly closed the line");
    requireReceiverStats(ls, verify_payload);
    twfRequire(splicestreamLength(ls->recv_stream) == 0, "receiver retained consumed frame bytes");
    twfRequireNoLeakedBuffers();
    drainWorker(&fixture, 0);
    tosRequireNoProcessApiCall();
    fixtureTeardown(&fixture);
}

static void caseDatagramReceiverVerification(bool verify_payload)
{
    twfSetCase("SpeedTestClient datagram payload verification policy");
    speedtestclient_fixture_t fixture;
    line_t                   *line = prepareReceiver(&fixture, verify_payload, kSpeedTestClientModeUdp);
    uint8_t                   wire[kSpeedTestClientFrameHeaderSize + 31];
    uint32_t                  length = receiverDataFrame(wire, 23, 0, true, kSpeedTestClientModeUdp);
    speedtestclientProcessIncoming(fixture.speed, line, receiverInput(line, wire, length, false));
    length = receiverDataFrame(wire, 31, 1, false, kSpeedTestClientModeUdp);
    speedtestclientProcessIncoming(fixture.speed, line, receiverInput(line, wire, length, false));
    twfRequire(lineIsAlive(line), "datagram reception unexpectedly closed the line");
    requireReceiverStats(lineGetState(line, fixture.speed), verify_payload);
    twfRequireNoLeakedBuffers();
    drainWorker(&fixture, 0);
    tosRequireNoProcessApiCall();
    fixtureTeardown(&fixture);
}

static void caseMalformedReceiverLengthClosesLine(bool splice)
{
    twfSetCase("SpeedTestClient rejects malformed DATA length with verification disabled");
    speedtestclient_fixture_t fixture;
    line_t                   *line  = prepareReceiver(&fixture, false, kSpeedTestClientModeTcp);
    speedtestclient_tstate_t *state = tunnelGetState(fixture.speed);
    uint8_t                   header[kSpeedTestClientFrameHeaderSize];
    speedtestclientWriteHeader(
        header, kSpeedTestClientFrameData, kSpeedTestClientFlagDownload, 0, state->payload_size + 1U, 0, 0, 0, 0);
    lineRef(line);
    speedtestclientProcessIncoming(fixture.speed, line, receiverInput(line, header, sizeof(header), splice));
    twfRequire(! lineIsAlive(line) && state->owned_lines[0] == NULL,
               "malformed DATA length left the owned line alive or published");
    twfRequireLineStateZeroed(line, fixture.speed, "malformed DATA length retained parser state");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "malformed DATA length did not finish transport once");
    lineUnref(line);
    twfRequireNoLeakedBuffers();
    drainWorker(&fixture, 0);
    tosRequireNoProcessApiCall();
    fixtureTeardown(&fixture);
}

int main(void)
{
    testSpliceInventoryInitialize(0);
    caseWorkerStopDrainsOnlyItsPublishedSlots();
    caseRequiredStartupFailuresPropagateStartupStatus();
    caseAcceptedQueuedTimerAdmissionClosureUsesCleanup();
    caseEstStopsAfterSendAdmissionClosesLine();
    caseReportRejectionClosesOwnedLine();
    caseAcceptedReportCancellationLeavesOwnerDrainSafe();
    caseFragmentedReceiverFrames(false, false);
    caseFragmentedReceiverFrames(true, false);
    caseDatagramReceiverVerification(false);
    caseDatagramReceiverVerification(true);
    caseMalformedReceiverLengthClosesLine(false);
#if WW_HAVE_SPLICE
    caseFragmentedReceiverFrames(false, true);
    caseFragmentedReceiverFrames(true, true);
    caseMalformedReceiverLengthClosesLine(true);
#endif
    puts("SpeedTestClient orderly shutdown tests passed");
    return 0;
}
