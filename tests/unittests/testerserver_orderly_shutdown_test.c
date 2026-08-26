/*
 * TesterServer runtime-verdict failure injection.
 *
 * The mirror image of the TesterClient cases: a peer that sends the wrong
 * request bytes is a runtime verdict that recycles its buffer and requests an
 * orderly shutdown, while an impossible payload-generator state and the death
 * of a persistent worker packet line are invariants that must hard-abort.
 */
#include "TesterServer/structure.h"

#include "tunnel_orderly_shutdown_harness.h"

enum
{
    kTestLargeBufferSize = 1 << 20,
    // Packet mode responses are always taken from the small pool, so it has to
    // hold a maximum-length packet.
    kTestSmallBufferSize = kMaxAllowedPacketLength,
    // Five chunks give a 64-byte packet chunk and a 32-byte stream chunk, both
    // far too wide for one corrupted byte to accidentally match another flow id.
    kTestChunkCount       = 5,
    kTestPacketChunkIndex = 4,
    kTestStreamChunkIndex = 3
};

typedef struct testerserver_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *tester;
    tunnel_t        *next;
    line_t          *line;
} testerserver_fixture_t;

static bool         refuse_next_line_task;
static bool         refuse_next_delayed_line_task;
static unsigned int line_task_submissions;
static unsigned int delayed_line_task_submissions;

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
    line_task_submissions += 1U;
    if (! refuse_next_line_task)
    {
        return __real_lineScheduleTask(line, task, t, on_cancel);
    }

    refuse_next_line_task = false;
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
    if (! refuse_next_delayed_line_task)
    {
        return __real_lineScheduleDelayedTask(line, task, delay_ms, t, on_cancel);
    }

    refuse_next_delayed_line_task = false;
    lineRef(line);
    if (on_cancel != NULL)
    {
        on_cancel(t, line, kLineTaskCancelResourceFailure);
    }
    lineUnref(line);
    return kLineTaskSubmitRejectedSettled;
}

static void fixtureSetup(testerserver_fixture_t *fixture, bool packet_mode, bool packet_stateless)
{
    memoryZero(&fixture->trace, sizeof(fixture->trace));
    twfWorkerEnvSetupWithSmallBuffers(&fixture->env, kTestLargeBufferSize, kTestSmallBufferSize, 0);

    fixture->prev   = twfCreatePrevTunnel(&fixture->trace);
    fixture->tester = tunnelCreate(NULL, sizeof(testerserver_tstate_t), sizeof(testerserver_lstate_t));
    twfRequire(fixture->tester != NULL, "failed to create the TesterServer tunnel");
    fixture->next = twfCreateNextTunnel(&fixture->trace);

    tunnelBind(fixture->prev, fixture->tester);
    tunnelBind(fixture->tester, fixture->next);

    testerserver_tstate_t *ts = tunnelGetState(fixture->tester);
    ts->chunk_count           = kTestChunkCount;
    ts->packet_mode           = packet_mode;
    ts->packet_stateless      = packet_stateless;
    ts->split_payload_burst   = 1;

    fixture->line = twfLineCreate(fixture->tester->lstate_size);

    testerserver_lstate_t *ls = lineGetState(fixture->line, fixture->tester);
    testerserverLinestateInitialize(ls, lineGetBufferPool(fixture->line));
}

static void fixtureTeardown(testerserver_fixture_t *fixture)
{
    testerserver_lstate_t *ls = lineGetState(fixture->line, fixture->tester);
    testerserverLinestateDestroy(ls);
    twfLineDestroy(fixture->line);
}

/**
 * Build a well-formed request chunk and flip one byte, which is what a
 * misbehaving peer produces.
 */
static sbuf_t *makeCorruptRequest(testerserver_fixture_t *fixture, uint8_t chunk_index)
{
    sbuf_t *buf = testerserverCreatePayload(fixture->tester,
                                            fixture->line,
                                            chunk_index,
                                            0,
                                            testerserverGetChunkSize(fixture->tester, chunk_index),
                                            kTesterServerDirectionRequest);
    twfRequire(buf != NULL, "the payload generator must never return NULL");

    uint8_t *bytes = sbufGetMutablePtr(buf);
    bytes[sbufGetLength(buf) - 1U] ^= 0xFFU;
    return buf;
}

static void requireVerdictLeftNothingBehind(testerserver_fixture_t *fixture)
{
    tosRequireAcceptedRequest(1);
    twfRequireNoLeakedBuffers();
    twfRequireEqualU32(fixture->trace.prev_payload, 0, "a failed verdict must not answer the peer");
    twfRequireEqualU32(fixture->trace.next_payload, 0, "a failed verdict must not forward upstream");

    testerserver_lstate_t *ls = lineGetState(fixture->line, fixture->tester);
    twfRequireEqualU32(bufferqueueGetBufCount(&ls->response_queue), 0, "a failed verdict must not queue a response");
    twfRequire(! ls->response_ready, "a failed verdict must not mark the request verified");
}

static void requireTesterStateDestroyed(testerserver_fixture_t *fixture)
{
    const uint8_t *bytes = lineGetState(fixture->line, fixture->tester);
    const size_t   size  = tunnelGetCorrectAlignedLineStateSize(sizeof(testerserver_lstate_t));

    for (size_t i = 0; i < size; ++i)
    {
        twfRequire(bytes[i] == 0, "a terminal Finish verdict must destroy the complete TesterServer line state");
    }
}

// ---------------------------------------------------------------------------
// Category B: an incomplete stream ends before verification
// ---------------------------------------------------------------------------

static void caseIncompleteFinishDestroysLineState(void)
{
    twfSetCase("testerserver incomplete finish");
    tosResetProcessApi(true);

    testerserver_fixture_t fixture;
    fixtureSetup(&fixture, false, false);

    testerserverTunnelUpStreamFinish(fixture.tester, fixture.line);

    tosRequireAcceptedRequest(1);
    requireTesterStateDestroyed(&fixture);

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category B: a packet-mode request mismatch
// ---------------------------------------------------------------------------

static void casePacketRequestMismatch(void)
{
    twfSetCase("testerserver packet request mismatch");
    tosResetProcessApi(true);

    testerserver_fixture_t fixture;
    fixtureSetup(&fixture, true, false);

    testerserver_lstate_t *ls = lineGetState(fixture.line, fixture.tester);
    // Chunk 0 only carries the flow id, so a verifiable chunk index is needed.
    ls->request_rx_index = kTestPacketChunkIndex;

    const uint32_t recycles_before = twfRecycleCount();
    sbuf_t        *request         = makeCorruptRequest(&fixture, kTestPacketChunkIndex);

    testerserverTunnelUpStreamPayload(fixture.tester, fixture.line, request);

    twfRequireEqualU32(twfRecycleCount() - recycles_before, 1, "the request buffer must be recycled exactly once");
    requireVerdictLeftNothingBehind(&fixture);
    twfRequireEqualU32(ls->request_rx_index, kTestPacketChunkIndex, "a failed verdict must not advance the index");

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category B: a stateless packet-mode request mismatch
// ---------------------------------------------------------------------------

static void caseStatelessPacketRequestMismatch(void)
{
    twfSetCase("testerserver stateless packet request mismatch");
    tosResetProcessApi(true);

    testerserver_fixture_t fixture;
    fixtureSetup(&fixture, true, true);

    const uint32_t recycles_before = twfRecycleCount();
    // The stateless path infers the chunk index from the packet size and then
    // tries every flow id, so a corrupted wide chunk cannot match any of them.
    sbuf_t *request = makeCorruptRequest(&fixture, kTestPacketChunkIndex);

    testerserverTunnelUpStreamPayload(fixture.tester, fixture.line, request);

    twfRequireEqualU32(twfRecycleCount() - recycles_before, 1, "the request buffer must be recycled exactly once");
    requireVerdictLeftNothingBehind(&fixture);

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Packet-line task refusal is a verdict, never a packet Finish
// ---------------------------------------------------------------------------

static void casePacketResponseScheduleRefusalKeepsStateForWorkerStop(void)
{
    twfSetCase("testerserver packet response schedule refusal");
    tosResetProcessApi(true);

    testerserver_fixture_t fixture;
    fixtureSetup(&fixture, true, false);

    testerserver_lstate_t *ls = lineGetState(fixture.line, fixture.tester);
    ls->response_to_next      = false;
    bufferqueuePushBack(&ls->response_queue,
                        testerserverCreatePayload(fixture.tester,
                                                  fixture.line,
                                                  0,
                                                  0,
                                                  testerserverGetChunkSize(fixture.tester, 0),
                                                  kTesterServerDirectionResponse));

    line_task_submissions = 0;
    refuse_next_line_task = true;
    testerserverScheduleResponseSend(fixture.tester, fixture.line, ls);

    tosRequireAcceptedRequest(1);
    twfRequire(lineIsAlive(fixture.line), "schedule refusal destroyed the chain-owned packet line");
    twfRequireEqualU32(fixture.trace.prev_finish, 0, "schedule refusal emitted a packet-line Finish");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "schedule refusal reflected a packet-line Finish");
    twfRequire(ls->terminal_failure, "schedule refusal did not publish a terminal packet verdict");
    twfRequire(! ls->response_send_scheduled, "rejected response remained marked as scheduled");
    twfRequireEqualU32(
        bufferqueueGetBufCount(&ls->response_queue), 1, "schedule refusal settled owner-worker queue state early");
    twfRequireEqualU32(line_task_submissions, 1, "initial response used the wrong number of task submissions");

    /* Resume or another payload root may arrive before the coordinator closes
     * this worker. Neither is allowed to restart response scheduling. */
    testerserverScheduleResponseSend(fixture.tester, fixture.line, ls);
    twfRequireEqualU32(line_task_submissions, 1, "terminal packet verdict restarted response scheduling");

    const uint32_t recycles_before = twfRecycleCount();
    sbuf_t        *late_request    = testerserverCreatePayload(
        fixture.tester, fixture.line, 0, 0, testerserverGetChunkSize(fixture.tester, 0), kTesterServerDirectionRequest);
    testerserverTunnelDownStreamPayload(fixture.tester, fixture.line, late_request);
    twfRequireEqualU32(
        twfRecycleCount() - recycles_before, 1, "terminal packet verdict did not discard a later payload once");
    twfRequireEqualU32(
        bufferqueueGetBufCount(&ls->response_queue), 1, "terminal packet verdict retained a later response");
    twfRequireEqualU32(line_task_submissions, 1, "late packet payload restarted response scheduling");

    fixtureTeardown(&fixture);
    twfRequireNoLeakedBuffers();
}

typedef struct testerserver_borrowed_fixture_s
{
    twf_worker_env_t env;
    twf_line_pool_t  lines;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *tester;
    tunnel_t        *next;
    line_t          *line;
} testerserver_borrowed_fixture_t;

static void testerserverOwnerFinish(tunnel_t *t, line_t *l)
{
    twf_trace_t *trace = *(twf_trace_t **) tunnelGetState(t);
    ++trace->prev_finish;
    twfRecord(trace, 'f');
    lineDestroy(l);
}

static void borrowedFixtureSetup(testerserver_borrowed_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetupWithSmallBuffers(&fixture->env, kTestLargeBufferSize, kTestSmallBufferSize, 0);

    fixture->prev   = twfCreatePrevTunnel(&fixture->trace);
    fixture->tester = tunnelCreate(NULL, sizeof(testerserver_tstate_t), sizeof(testerserver_lstate_t));
    fixture->next   = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->tester != NULL, "failed to create the borrowed TesterServer fixture");
    tunnelBind(fixture->prev, fixture->tester);
    tunnelBind(fixture->tester, fixture->next);
    fixture->prev->fnFinD = testerserverOwnerFinish;

    testerserver_tstate_t *ts = tunnelGetState(fixture->tester);
    ts->chunk_count           = kTestChunkCount;
    ts->split_payload_burst   = 1;

    twfLinePoolSetup(&fixture->lines, fixture->tester->lstate_size, 4);
    fixture->line = twfLinePoolCreateLine(&fixture->lines);
    testerserverLinestateInitialize(lineGetState(fixture->line, fixture->tester), lineGetBufferPool(fixture->line));
}

static void borrowedFixtureTeardown(testerserver_borrowed_fixture_t *fixture)
{
    twfRequireEqualU32(
        (uint32_t) masterpoolGetCheckedOut(fixture->lines.master), 0, "borrowed TesterServer fixture retained a line");
    twfLinePoolTeardown(&fixture->lines);
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->tester);
    tunnelDestroy(fixture->prev);
    twfWorkerEnvTeardown(&fixture->env);
}

static void caseBorrowedResponseScheduleRefusalFinishesOwner(void)
{
    twfSetCase("testerserver borrowed response schedule refusal finishes its owner");
    tosResetProcessApi(true);

    testerserver_borrowed_fixture_t fixture;
    borrowedFixtureSetup(&fixture);
    testerserver_lstate_t *ls = lineGetState(fixture.line, fixture.tester);
    ls->response_ready        = true;

    lineRef(fixture.line);
    line_task_submissions         = 0;
    delayed_line_task_submissions = 0;
    refuse_next_line_task         = true;
    testerserverScheduleResponseSend(fixture.tester, fixture.line, ls);

    tosRequireAcceptedRequest(1);
    twfRequire(! lineIsAlive(fixture.line), "response refusal left the borrowed normal line alive");
    twfRequireLineStateZeroed(fixture.line, fixture.tester, "response refusal retained TesterServer state");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "response refusal did not finish toward the real owner");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "response refusal reflected Finish away from the owner");
    twfRequireEqualU32(line_task_submissions, 1, "response refusal used the wrong number of task submissions");
    twfRequireEqualU32(delayed_line_task_submissions, 0, "response refusal armed later response work");

    lineUnref(fixture.line);
    twfRequireNoLeakedBuffers();
    borrowedFixtureTeardown(&fixture);
}

static void caseBorrowedDelayedSplitRefusalFinishesOwner(void)
{
    twfSetCase("testerserver borrowed delayed split refusal finishes its owner");
    tosResetProcessApi(true);

    testerserver_borrowed_fixture_t fixture;
    borrowedFixtureSetup(&fixture);
    testerserver_tstate_t *ts  = tunnelGetState(fixture.tester);
    ts->max_payload_size       = 1;
    ts->split_payload_delay_ms = 1;

    testerserver_lstate_t *ls   = lineGetState(fixture.line, fixture.tester);
    ls->response_ready          = true;
    ls->response_send_scheduled = true;

    lineRef(fixture.line);
    line_task_submissions         = 0;
    delayed_line_task_submissions = 0;
    refuse_next_delayed_line_task = true;
    testerserverResponseSendTask(fixture.tester, fixture.line);

    tosRequireAcceptedRequest(1);
    twfRequire(! lineIsAlive(fixture.line), "delayed split refusal left the borrowed normal line alive");
    twfRequireLineStateZeroed(fixture.line, fixture.tester, "delayed split refusal retained its latch or state");
    twfRequireEqualU32(fixture.trace.prev_payload, 1, "delayed split fixture did not send one partial response");
    twfRequireEqualU32(fixture.trace.prev_finish, 1, "delayed split refusal did not finish toward the real owner");
    twfRequireEqualU32(fixture.trace.next_finish, 0, "delayed split refusal reflected Finish away from the owner");
    twfRequireEqualU32(line_task_submissions, 0, "delayed split refusal armed immediate response work");
    twfRequireEqualU32(delayed_line_task_submissions, 1, "delayed split refusal armed later response work");

    lineUnref(fixture.line);
    twfRequireNoLeakedBuffers();
    borrowedFixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category B: a stream-mode request mismatch
// ---------------------------------------------------------------------------

static void caseStreamRequestMismatch(void)
{
    twfSetCase("testerserver stream request mismatch");
    tosResetProcessApi(true);

    testerserver_fixture_t fixture;
    fixtureSetup(&fixture, false, false);

    testerserver_lstate_t *ls = lineGetState(fixture.line, fixture.tester);
    ls->request_rx_index      = kTestStreamChunkIndex;

    const uint32_t recycles_before = twfRecycleCount();
    sbuf_t        *request         = makeCorruptRequest(&fixture, kTestStreamChunkIndex);

    // Pushed into the read stream, then read back out as a chunk this callback
    // owns; that extracted chunk is what must be recycled before the verdict.
    testerserverTunnelUpStreamPayload(fixture.tester, fixture.line, request);

    twfRequireEqualU32(twfRecycleCount() - recycles_before, 1, "the extracted chunk must be recycled exactly once");
    requireVerdictLeftNothingBehind(&fixture);
    twfRequireEqualU32(ls->request_rx_index, kTestStreamChunkIndex, "a failed verdict must not advance the index");

    fixtureTeardown(&fixture);
}

// ---------------------------------------------------------------------------
// Category B: the worker-0 handoff is refused
// ---------------------------------------------------------------------------

static void refusedHandoffBody(void *argument)
{
    discard argument;

    testerserver_fixture_t fixture;
    fixtureSetup(&fixture, true, false);

    testerserver_lstate_t *ls = lineGetState(fixture.line, fixture.tester);
    ls->request_rx_index      = kTestPacketChunkIndex;

    testerserverTunnelUpStreamPayload(
        fixture.tester, fixture.line, makeCorruptRequest(&fixture, kTestPacketChunkIndex));
}

static void caseRefusedHandoffAborts(void)
{
    twfSetCase("testerserver verdict with a refused worker-0 handoff");

    tosResetProcessApi(false);
    tosRequireChildExit("the refused-handoff verdict", refusedHandoffBody, NULL, kTosChildFallbackAbort);

    tosResetProcessApi(true);
}

// ---------------------------------------------------------------------------
// Category D: an impossible payload-generator state
// ---------------------------------------------------------------------------

static void payloadGeneratorInvariantBody(void *argument)
{
    discard argument;

    testerserver_fixture_t fixture;
    fixtureSetup(&fixture, true, false);

    // Packet mode may never split a chunk.
    twfRequire(testerserverGetChunkSize(fixture.tester, 1) > 1U, "chunk 1 must be splittable to drive this case");
    discard testerserverCreatePayload(fixture.tester, fixture.line, 1, 0, 1, kTesterServerDirectionResponse);
}

static void casePayloadGeneratorInvariantAborts(void)
{
    twfSetCase("testerserver impossible payload-generator state");

    // The handoff would be accepted, so reaching the hard abort proves this
    // branch never consults the orderly helper.
    tosResetProcessApi(true);
    tosRequireChildExit("the payload-generator invariant", payloadGeneratorInvariantBody, NULL, kTosChildDirectAbort);

    tosResetProcessApi(true);
}

// ---------------------------------------------------------------------------
// Category D: a persistent worker packet line dies during a response send
// ---------------------------------------------------------------------------

/**
 * A fake peer that kills the line while receiving the response, which is the
 * packet-line contract violation the send task must never survive.
 */
static void killLineOnPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    lineReuseBuffer(l, buf);
    l->alive = false;
}

static void packetLineDeathBody(void *argument)
{
    discard argument;

    testerserver_fixture_t fixture;
    fixtureSetup(&fixture, true, false);
    fixture.prev->fnPayloadD = killLineOnPayload;

    testerserver_lstate_t *ls = lineGetState(fixture.line, fixture.tester);
    ls->response_to_next      = false;
    bufferqueuePushBack(&ls->response_queue,
                        testerserverCreatePayload(fixture.tester,
                                                  fixture.line,
                                                  0,
                                                  0,
                                                  testerserverGetChunkSize(fixture.tester, 0),
                                                  kTesterServerDirectionResponse));

    testerserverResponseSendTask(fixture.tester, fixture.line);
}

static void casePacketLineDeathAborts(void)
{
    twfSetCase("testerserver packet line died during response send");

    tosResetProcessApi(true);
    tosRequireChildExit("the packet-line-death invariant", packetLineDeathBody, NULL, kTosChildDirectAbort);

    tosResetProcessApi(true);
}

// ---------------------------------------------------------------------------
// Packet-line state must be drained by the exact owning worker
// ---------------------------------------------------------------------------

static void casePacketWorkerStopSettlesOwnerState(void)
{
    enum
    {
        kWorkerCount = 2
    };

    twfSetCase("testerserver packet worker Stop settles worker-affine state");
    tosResetProcessApi(true);

    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, kWorkerCount, kTestLargeBufferSize, kTestSmallBufferSize);

    tunnel_t *tester = tunnelCreate(NULL, sizeof(testerserver_tstate_t), sizeof(testerserver_lstate_t));
    twfRequire(tester != NULL, "failed to create the packet worker-stop TesterServer fixture");

    tunnel_chain_t *chain = memoryAllocateZero(sizeof(tunnel_chain_t) + kWorkerCount * sizeof(generic_pool_t *));
    twfRequire(chain != NULL, "failed to allocate the packet worker-stop chain");
    line_t *packet_lines[kWorkerCount] = {0};
    chain->workers_count               = kWorkerCount;
    chain->contains_packet_node        = true;
    chain->finalized                   = true;
    chain->packet_lines                = packet_lines;
    tester->chain                      = chain;

    testerserver_tstate_t *ts = tunnelGetState(tester);
    ts->packet_mode           = true;

    const uint32_t recycles_before = twfRecycleCount();
    for (wid_t wid = 0; wid < kWorkerCount; ++wid)
    {
        line_t *line      = twfLineCreate(tester->lstate_size);
        line->wid         = wid;
        packet_lines[wid] = line;

        const wid_t            previous_wid = tosSetCurrentWorker(wid);
        testerserver_lstate_t *ls           = lineGetState(line, tester);
        testerserverLinestateInitialize(ls, lineGetBufferPool(line));

        sbuf_t *retained = bufferpoolGetSmallBuffer(lineGetBufferPool(line));
        sbufSetLength(retained, 1);
        bufferstreamPush(&ls->read_stream, retained);

        testerserverTunnelOnWorkerStop(tester, wid, wwLifecycleProcessShutdown());

        twfRequireLineStateZeroed(line, tester, "packet worker Stop left TesterServer state behind");
        twfRequire(lineIsAlive(line), "packet worker Stop destroyed the chain-owned packet line");

        /* A terminal packet flow can retain scalar progress after its stream
         * has already been settled. Stop must still invoke the full
         * destructor, not use the null pool as a proxy for zero state. */
        twfRequire(ls->read_stream.pool == NULL, "the first packet drain did not clear the stream pool");
        ls->request_rx_index  = 11;
        ls->response_tx_index = 11;
        ls->response_ready    = true;
        ls->response_sent     = true;
        ls->response_to_next  = true;
        testerserverTunnelOnWorkerStop(tester, wid, wwLifecycleProcessShutdown());
        twfRequireLineStateZeroed(
            line, tester, "packet worker Stop left terminal TesterServer scalars behind after its pool was cleared");

        discard tosSetCurrentWorker(previous_wid);
    }

    twfRequireEqualU32(
        twfRecycleCount() - recycles_before, kWorkerCount, "packet worker Stop did not recycle every retained buffer");
    twfRequireNoLeakedBuffers();
    tosRequireNoProcessApiCall();

    /* onDestroy runs after owner-worker drains and must not revisit their pools. */
    testerserverTunnelDestroy(tester, wwLifecycleProcessShutdown());
    for (wid_t wid = 0; wid < kWorkerCount; ++wid)
    {
        twfLineDestroy(packet_lines[wid]);
    }
    memoryFree(chain);
    tosWorkerEnvTeardown(&env);
}

static void residualPacketStateDestroyBody(void *argument)
{
    const bool terminal_scalars_only = (uintptr_t) argument != 0;

    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, 1, kTestLargeBufferSize, kTestSmallBufferSize);

    tunnel_t *tester = tunnelCreate(NULL, sizeof(testerserver_tstate_t), sizeof(testerserver_lstate_t));
    twfRequire(tester != NULL, "failed to create the residual TesterServer fixture");

    tunnel_chain_t *chain = memoryAllocateZero(sizeof(tunnel_chain_t) + sizeof(generic_pool_t *));
    twfRequire(chain != NULL, "failed to allocate the residual TesterServer chain");
    line_t *packet_lines[1]     = {twfLineCreate(tester->lstate_size)};
    chain->workers_count        = 1;
    chain->contains_packet_node = true;
    chain->finalized            = true;
    chain->packet_lines         = packet_lines;
    tester->chain               = chain;

    testerserver_tstate_t *ts = tunnelGetState(tester);
    ts->packet_mode           = true;
    testerserver_lstate_t *ls = lineGetState(packet_lines[0], tester);
    if (terminal_scalars_only)
    {
        twfRequire(ls->read_stream.pool == NULL, "the terminal-scalar fixture unexpectedly has a stream pool");
        ls->request_rx_index  = 11;
        ls->response_tx_index = 11;
        ls->response_ready    = true;
        ls->response_sent     = true;
        ls->response_to_next  = true;
    }
    else
    {
        testerserverLinestateInitialize(ls, lineGetBufferPool(packet_lines[0]));
        bufferstreamPush(&ls->read_stream, bufferpoolGetSmallBuffer(lineGetBufferPool(packet_lines[0])));
    }

    testerserverTunnelDestroy(tester, wwLifecycleProcessShutdown());
}

static void caseDestroyRejectsUndrainedFinalizedPacketState(void)
{
    twfSetCase("testerserver Destroy rejects undrained finalized packet state");
    tosResetProcessApi(true);
    tosRequireChildExit(
        "the undrained packet buffer state", residualPacketStateDestroyBody, NULL, kTosChildDirectAbort);
    tosRequireChildExit("terminal packet scalars with no stream pool",
                        residualPacketStateDestroyBody,
                        (void *) (uintptr_t) 1,
                        kTosChildDirectAbort);
    tosResetProcessApi(true);
}

typedef enum testerserver_finalized_geometry_case_e
{
    kTesterServerFinalizedGeometryMissingSlots,
    kTesterServerFinalizedGeometryMissingPacketSlot,
    kTesterServerFinalizedGeometryOutOfRangeWorker,
    kTesterServerFinalizedGeometryWrongCurrentWorker,
    kTesterServerFinalizedGeometryPacketModeWithoutPacketTopology,
    kTesterServerFinalizedGeometryDestroyMissingSlots,
    kTesterServerFinalizedGeometryDestroyMissingPacketSlot,
    kTesterServerFinalizedGeometryDestroyWrongPacketOwner,
    kTesterServerFinalizedGeometryDestroyPacketModeWithoutPacketTopology,
} testerserver_finalized_geometry_case_e;

static void finalizedPacketGeometryAbortBody(void *argument)
{
    const testerserver_finalized_geometry_case_e geometry =
        (testerserver_finalized_geometry_case_e) (uintptr_t) argument;

    enum
    {
        kWorkerCount = 2
    };

    tos_worker_env_t env;
    tosWorkerEnvSetup(&env, kWorkerCount, kTestLargeBufferSize, kTestSmallBufferSize);

    tunnel_t *tester = tunnelCreate(NULL, sizeof(testerserver_tstate_t), sizeof(testerserver_lstate_t));
    twfRequire(tester != NULL, "failed to create the finalized-geometry TesterServer fixture");

    tunnel_chain_t *chain = memoryAllocateZero(sizeof(tunnel_chain_t) + kWorkerCount * sizeof(generic_pool_t *));
    twfRequire(chain != NULL, "failed to allocate the finalized-geometry TesterServer chain");
    line_t *packet_lines[kWorkerCount] = {0};
    chain->workers_count               = kWorkerCount;
    chain->contains_packet_node        = true;
    chain->finalized                   = true;
    chain->packet_lines                = packet_lines;
    tester->chain                      = chain;

    testerserver_tstate_t *ts = tunnelGetState(tester);
    ts->packet_mode           = true;

    switch (geometry)
    {
    case kTesterServerFinalizedGeometryMissingSlots:
        chain->packet_lines = NULL;
        testerserverTunnelOnWorkerStop(tester, 0, wwLifecycleProcessShutdown());
        break;
    case kTesterServerFinalizedGeometryMissingPacketSlot:
        testerserverTunnelOnWorkerStop(tester, 0, wwLifecycleProcessShutdown());
        break;
    case kTesterServerFinalizedGeometryOutOfRangeWorker:
        testerserverTunnelOnWorkerStop(tester, kWorkerCount, wwLifecycleProcessShutdown());
        break;
    case kTesterServerFinalizedGeometryWrongCurrentWorker: {
        line_t *line    = twfLineCreate(tester->lstate_size);
        line->wid       = 1;
        packet_lines[1] = line;
        discard tosSetCurrentWorker(0);
        testerserverTunnelOnWorkerStop(tester, 1, wwLifecycleProcessShutdown());
        break;
    }
    case kTesterServerFinalizedGeometryPacketModeWithoutPacketTopology: {
        line_t *line                = twfLineCreate(tester->lstate_size);
        line->wid                   = 0;
        packet_lines[0]             = line;
        chain->contains_packet_node = false;
        testerserverTunnelOnWorkerStop(tester, 0, wwLifecycleProcessShutdown());
        break;
    }
    case kTesterServerFinalizedGeometryDestroyMissingSlots:
        chain->packet_lines = NULL;
        testerserverTunnelDestroy(tester, wwLifecycleProcessShutdown());
        break;
    case kTesterServerFinalizedGeometryDestroyMissingPacketSlot:
        testerserverTunnelDestroy(tester, wwLifecycleProcessShutdown());
        break;
    case kTesterServerFinalizedGeometryDestroyWrongPacketOwner: {
        line_t *line    = twfLineCreate(tester->lstate_size);
        line->wid       = 1;
        packet_lines[0] = line;
        testerserverTunnelDestroy(tester, wwLifecycleProcessShutdown());
        break;
    }
    case kTesterServerFinalizedGeometryDestroyPacketModeWithoutPacketTopology: {
        line_t *line                = twfLineCreate(tester->lstate_size);
        line->wid                   = 0;
        packet_lines[0]             = line;
        chain->contains_packet_node = false;
        testerserverTunnelDestroy(tester, wwLifecycleProcessShutdown());
        break;
    }
    }
}

static void caseFinalizedPacketGeometryAborts(void)
{
    twfSetCase("testerserver finalized packet geometry is release-fatal");
    tosResetProcessApi(true);

    tosRequireChildExit("missing finalized packet-line slots",
                        finalizedPacketGeometryAbortBody,
                        (void *) (uintptr_t) kTesterServerFinalizedGeometryMissingSlots,
                        kTosChildDirectAbort);
    tosRequireChildExit("a missing finalized packet line",
                        finalizedPacketGeometryAbortBody,
                        (void *) (uintptr_t) kTesterServerFinalizedGeometryMissingPacketSlot,
                        kTosChildDirectAbort);
    tosRequireChildExit("an out-of-range finalized packet worker",
                        finalizedPacketGeometryAbortBody,
                        (void *) (uintptr_t) kTesterServerFinalizedGeometryOutOfRangeWorker,
                        kTosChildDirectAbort);
    tosRequireChildExit("a foreign worker Stop callback",
                        finalizedPacketGeometryAbortBody,
                        (void *) (uintptr_t) kTesterServerFinalizedGeometryWrongCurrentWorker,
                        kTosChildDirectAbort);
    tosRequireChildExit("packet mode with a stream-only topology",
                        finalizedPacketGeometryAbortBody,
                        (void *) (uintptr_t) kTesterServerFinalizedGeometryPacketModeWithoutPacketTopology,
                        kTosChildDirectAbort);
    tosRequireChildExit("Destroy missing finalized packet-line slots",
                        finalizedPacketGeometryAbortBody,
                        (void *) (uintptr_t) kTesterServerFinalizedGeometryDestroyMissingSlots,
                        kTosChildDirectAbort);
    tosRequireChildExit("Destroy missing a finalized packet line",
                        finalizedPacketGeometryAbortBody,
                        (void *) (uintptr_t) kTesterServerFinalizedGeometryDestroyMissingPacketSlot,
                        kTosChildDirectAbort);
    tosRequireChildExit("Destroy with a wrong-owner finalized packet line",
                        finalizedPacketGeometryAbortBody,
                        (void *) (uintptr_t) kTesterServerFinalizedGeometryDestroyWrongPacketOwner,
                        kTosChildDirectAbort);
    tosRequireChildExit("Destroy packet mode with a stream-only topology",
                        finalizedPacketGeometryAbortBody,
                        (void *) (uintptr_t) kTesterServerFinalizedGeometryDestroyPacketModeWithoutPacketTopology,
                        kTosChildDirectAbort);

    tosResetProcessApi(true);
}

int main(void)
{
    caseIncompleteFinishDestroysLineState();
    casePacketRequestMismatch();
    caseStatelessPacketRequestMismatch();
    casePacketResponseScheduleRefusalKeepsStateForWorkerStop();
    caseBorrowedResponseScheduleRefusalFinishesOwner();
    caseBorrowedDelayedSplitRefusalFinishesOwner();
    caseStreamRequestMismatch();
    caseRefusedHandoffAborts();
    casePayloadGeneratorInvariantAborts();
    casePacketLineDeathAborts();
    casePacketWorkerStopSettlesOwnerState();
    caseDestroyRejectsUndrainedFinalizedPacketState();
    caseFinalizedPacketGeometryAborts();

    printf("testerserver_orderly_shutdown_test: all cases passed\n");
    return 0;
}
