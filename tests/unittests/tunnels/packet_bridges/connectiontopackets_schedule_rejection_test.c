/*
 * Covers: connectiontopackets schedule rejection; the explicit inputs, callbacks and expected results
 * below define this suite.
 * Setup: Real runtime/component code with the explicit worker/line/neighbour fixture and any linker
 * seams shown below. Line and buffer settlement remains the scenario owner's responsibility.
 * Cases: caseOwnerRetryRefusalPublishesAndDrainsTerminalLine,
 * caseCreditedDeliveryRefusalTransfersBufferAndRetainsPbuf, casePendingBudgetAllowsOneReadOfHeadroom,
 * caseTerminalPayloadReentry, caseStopOrdering
 * Checks: Assertion labels include: test engine entry refused; ConnectionToPackets read PCB statistics
 * without the owner engine; lwIP did not publish TCP PCB pool statistics; ConnectionToPackets submitted
 * an unexpected no-buffer task
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.connectiontopackets_schedule_rejection_unit
 */
/* Real CTP owner-engine callbacks reconcile refused scheduled work without
 * losing borrowed-line, pbuf or buffer ownership. */

#include "ConnectionToPackets/structure.h"

#include "fixtures/failure/tunnel_orderly_shutdown_harness.h"
#include "fixtures/lwip/lwip_test_runtime.h"

#include "lwip/stats.h"
#include "lwip/tcpip.h"

bool __wrap_signalmanagerRequestShutdownPreservingAcceptedStatus(int exit_code);
bool __wrap_signalmanagerRequestShutdownPreservingAcceptedStatus(int exit_code)
{
    return __wrap_requestProgramShutdown(exit_code);
}

typedef enum ctp_submit_expectation_e
{
    kCtpSubmitNone = 0,
    kCtpSubmitControl,
    kCtpSubmitBufferedDelivery,
} ctp_submit_expectation_t;

typedef struct ctp_fixture_s
{
    twf_worker_env_t  env;
    twf_trace_t       trace;
    tunnel_t         *prev;
    tunnel_t         *ctp;
    tunnel_chain_t   *chain;
    line_t           *line;
    line_t           *packet_line;
    uint32_t          owner_finish_calls;
    ww_lwip_engine_t *engine;
} ctp_fixture_t;

static uint32_t                 g_pool_size = 4096;
static ctp_fixture_t           *g_fixture;
static ctp_submit_expectation_t g_submit_expectation;
static uint32_t                 g_schedule_calls;
static uint32_t                 g_buffer_settlements;
static ww_lwip_engine_t        *test_previous;
static unsigned                 tcp_write_calls, tcp_write_fail_call, tcp_output_calls;
err_t                           __real_tcp_write(struct tcp_pcb *, const void *, u16_t, u8_t);
err_t                           __wrap_tcp_write(struct tcp_pcb *, const void *, u16_t, u8_t);
err_t                           __wrap_tcp_write(struct tcp_pcb *pcb, const void *data, u16_t length, u8_t flags)
{
    if (++tcp_write_calls == tcp_write_fail_call)
        return ERR_MEM;
    return __real_tcp_write(pcb, data, length, flags);
}
err_t __real_tcp_output(struct tcp_pcb *);
err_t __wrap_tcp_output(struct tcp_pcb *);
err_t __wrap_tcp_output(struct tcp_pcb *pcb)
{
    ++tcp_output_calls;
    return __real_tcp_output(pcb);
}

static void enterEngine(void)
{
    twfRequire(wwLwipEngineEnter(g_fixture->engine, &test_previous), "test engine entry refused");
}
static void leaveEngine(void)
{
    wwLwipEngineLeave(g_fixture->engine, test_previous);
}

line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel);
line_task_submit_result_e __wrap_lineScheduleTaskWithBuf(line_t *const line, LineTaskFnWithBuf task, tunnel_t *t,
                                                         sbuf_t *buf, LineTaskCancelFn on_cancel);

static uint32_t ctpTcpPcbUsedLocked(void)
{
    twfRequire(wwLwipEngineCurrent() == g_fixture->engine,
               "ConnectionToPackets read PCB statistics without the owner engine");
    twfRequire(lwip_stats.memp[MEMP_TCP_PCB] != NULL, "lwIP did not publish TCP PCB pool statistics");
    return (uint32_t) lwip_stats.memp[MEMP_TCP_PCB]->used;
}

static uint32_t ctpTcpPcbUsed(void)
{
    enterEngine();
    const uint32_t used = ctpTcpPcbUsedLocked();
    leaveEngine();
    return used;
}

line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel)
{
    ctp_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL && g_submit_expectation == kCtpSubmitControl,
               "ConnectionToPackets submitted an unexpected no-buffer task");
    twfRequire(line == fixture->line && t == fixture->ctp && task == ctpResumeWriteTask,
               "ConnectionToPackets submitted the wrong control task");
    twfRequire(on_cancel == NULL, "ConnectionToPackets requested lock-reentrant cancellation notification");
    twfRequire(wwLwipEngineCurrent() == g_fixture->engine,
               "ConnectionToPackets control submission did not hold the owner engine");
    twfRequire(lineIsOnCurrentWorker(line),
               "ConnectionToPackets control refusal did not originate from its owner engine");

    lineRef(line);
    lineUnref(line);
    ++g_schedule_calls;
    return kLineTaskSubmitRejectedSettled;
}

line_task_submit_result_e __wrap_lineScheduleTaskWithBuf(line_t *const line, LineTaskFnWithBuf task, tunnel_t *t,
                                                         sbuf_t *buf, LineTaskCancelFn on_cancel)
{
    ctp_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL && g_submit_expectation == kCtpSubmitBufferedDelivery,
               "ConnectionToPackets submitted an unexpected buffered task");
    twfRequire(line == fixture->line && t == fixture->ctp && task == ctpDeliverPayloadTask,
               "ConnectionToPackets submitted the wrong buffered task");
    twfRequire(on_cancel == NULL, "ConnectionToPackets requested lock-reentrant cancellation notification");
    twfRequire(wwLwipEngineCurrent() == g_fixture->engine,
               "ConnectionToPackets buffered submission did not hold the owner engine");
    twfRequire(lineIsOnCurrentWorker(line),
               "ConnectionToPackets buffered delivery did not originate from the line owner");

    /* Synchronous owner-worker refusal: the real scheduler retains the line,
     * then recycles the unconditionally transferred buffer before returning. */
    lineRef(line);
    lineReuseBuffer(line, buf);
    lineUnref(line);
    ++g_schedule_calls;
    ++g_buffer_settlements;
    return kLineTaskSubmitRejectedSettled;
}

static void ctpOwnerFinish(tunnel_t *prev, line_t *line)
{
    ctp_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL && prev == fixture->prev && line == fixture->line,
               "ConnectionToPackets finished an unexpected borrowed line");
    ++fixture->owner_finish_calls;
    ++fixture->trace.prev_finish;
    twfRecord(&fixture->trace, 'f');
    lineDestroy(line);
}

static void ctpFixtureSetup(ctp_fixture_t *fixture)
{
    memoryZero(fixture, sizeof(*fixture));
    twfWorkerEnvSetupWithBufferSizes(&fixture->env,
                                     min(g_pool_size, (uint32_t) LARGE_BUFFER_SIZE_RAM_HIGH),
                                     min(g_pool_size, (uint32_t) LARGE_BUFFER_SIZE_RAM_HIGH),
                                     0,
                                     g_pool_size,
                                     g_pool_size);

    fixture->engine = wwLwipEngineCreate(0, fixture->env.loop);
    twfRequire(fixture->engine != NULL, "failed to create owner engine");

    fixture->prev = twfCreatePrevTunnel(&fixture->trace);
    fixture->ctp  = tunnelCreate(NULL, sizeof(ctp_tstate_t), sizeof(ctp_lstate_t));
    twfRequire(fixture->ctp != NULL, "failed to create the ConnectionToPackets fixture tunnel");
    tunnelBind(fixture->prev, fixture->ctp);
    fixture->prev->fnFinD = ctpOwnerFinish;

    fixture->chain = tunnelchainCreate(1);
    twfRequire(fixture->chain != NULL, "failed to create the ConnectionToPackets fixture chain");
    fixture->chain->sum_line_state_size  = fixture->ctp->lstate_size;
    fixture->chain->contains_packet_node = true;
    tunnelchainFinalize(fixture->chain);
    twfRequire(fixture->chain->finalized, "failed to finalize the ConnectionToPackets fixture chain");
    fixture->ctp->chain  = fixture->chain;
    fixture->packet_line = tunnelchainGetWorkerPacketLine(fixture->chain, 0);
    twfRequire(fixture->packet_line != NULL && lineIsAlive(fixture->packet_line),
               "ConnectionToPackets fixture has no live packet line");

    ctp_tstate_t *state   = tunnelGetState(fixture->ctp);
    state->netifs_count   = 1;
    state->terminal_lines = memoryAllocateZero(sizeof(*state->terminal_lines));
    state->active_lines   = memoryAllocateZero(sizeof(*state->active_lines));
    twfRequire(state->active_lines != NULL, "failed to allocate active inventory");
    twfRequire(state->terminal_lines != NULL, "failed to allocate the CTP terminal registry");
    twfRequire(rwlockTryInit(&state->flows_lock), "failed to initialize the CTP flow lock");
    atomic_init(&state->stopping, false);
    quiescenceGateInit(&state->prev_gate);
    quiescenceGateInit(&state->next_gate);
    quiescenceGateInit(&state->packet_ingress_gate);
    twfRequire(quiescenceGateOpen(&state->prev_gate), "failed to open the CTP previous-callback gate");
    twfRequire(quiescenceGateOpen(&state->next_gate), "failed to open the CTP next-callback gate");
    twfRequire(quiescenceGateOpen(&state->packet_ingress_gate), "failed to open the CTP packet-ingress gate");

    fixture->line = lineCreate(tunnelchainGetLinePools(fixture->chain), 0);
    ctpLinestateInitialize(lineGetState(fixture->line, fixture->ctp), fixture->ctp, fixture->line, kCtpLineKindTcp);

    ((ctp_lstate_t *) lineGetState(fixture->line, fixture->ctp))->engine = fixture->engine;
    g_fixture                                                            = fixture;
    g_submit_expectation                                                 = kCtpSubmitNone;
    g_schedule_calls                                                     = 0;
    g_buffer_settlements                                                 = 0;
}

static void ctpFixtureRequirePacketLineAlive(const ctp_fixture_t *fixture)
{
    twfRequire(fixture->packet_line != NULL && lineIsAlive(fixture->packet_line),
               "ConnectionToPackets destroyed the chain-owned packet line");
}

static void ctpFixtureTeardown(ctp_fixture_t *fixture)
{
    twfRequire(fixture->line == NULL, "ConnectionToPackets fixture retained a normal line at teardown");
    ctpFixtureRequirePacketLineAlive(fixture);
    twfRequireNoLeakedBuffers();

    ctp_tstate_t *state = tunnelGetState(fixture->ctp);
    rwlockDestroy(&state->flows_lock);
    twfRequire(state->active_lines[0] == NULL, "borrowed line inventory not empty");
    memoryFree(state->active_lines);
    memoryFree(state->terminal_lines);
    state->terminal_lines = NULL;

    tunnelchainDestroy(fixture->chain);
    tunnelDestroy(fixture->ctp);
    tunnelDestroy(fixture->prev);
    g_fixture = NULL;
    wwLwipEngineDestroy(fixture->engine);
    twfWorkerEnvTeardown(&fixture->env);
}

static struct tcp_pcb *ctpAttachTestPcb(ctp_fixture_t *fixture, uint32_t pcb_baseline)
{
    ctp_lstate_t *ls = lineGetState(fixture->line, fixture->ctp);

    enterEngine();
    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
    twfRequire(pcb != NULL, "lwIP could not allocate a CTP test PCB");
    twfRequireEqualU32(
        ctpTcpPcbUsedLocked(), pcb_baseline + 1U, "CTP test PCB allocation did not raise the used-count once");
    ls->tcp_pcb = pcb;
    tcp_arg(pcb, ls);
    tcp_recv(pcb, ctpTcpRecvCallback);
    tcp_sent(pcb, ctpTcpSentCallback);
    tcp_poll(pcb, ctpTcpPollCallback, kCtpWritePollInterval);
    tcp_err(pcb, ctpTcpErrorCallback);
    leaveEngine();
    return pcb;
}

static void ctpCloseFixtureLine(ctp_fixture_t *fixture)
{
    line_t *line = fixture->line;
    lineRef(line);
    ctpCloseLineTowardPrevWithoutDrain(fixture->ctp, line);
    twfRequire(! lineIsAlive(line), "CTP normal-line owner did not destroy the closed line");
    twfRequireLineStateZeroed(line, fixture->ctp, "CTP close left line state alive");
    twfRequireEqualU32(twfLineRefCount(line), 1, "CTP close leaked a physical line reference");
    lineUnref(line);
    fixture->line = NULL;
}

static void caseOwnerRetryRefusalPublishesAndDrainsTerminalLine(void)
{
    twfSetCase("ConnectionToPackets owner retry refusal inside its engine");
    tosResetProcessApi(true);

    ctp_fixture_t fixture;
    ctpFixtureSetup(&fixture);
    const uint32_t  pcb_baseline = ctpTcpPcbUsed();
    struct tcp_pcb *pcb          = ctpAttachTestPcb(&fixture, pcb_baseline);
    ctp_lstate_t   *ls           = lineGetState(fixture.line, fixture.ctp);
    ls->connected                = true;
    ls->write_blocked            = true;
    ls->write_poll_armed         = true;

    g_submit_expectation = kCtpSubmitControl;
    enterEngine();
    const err_t result = ctpTcpPollCallback(ls, pcb);
    twfRequireEqualU32(ctpTcpPcbUsedLocked(), pcb_baseline, "CTP retry refusal leaked its detached TCP PCB");
    leaveEngine();
    g_submit_expectation = kCtpSubmitNone;

    ctp_tstate_t *state = tunnelGetState(fixture.ctp);
    twfRequire(result == ERR_ABRT, "CTP retry refusal did not report the aborted PCB");
    twfRequireEqualU32(g_schedule_calls, 1, "CTP retry refusal submitted the wrong number of tasks");
    twfRequire(! ls->write_retry_queued && ! ls->write_poll_armed,
               "CTP retry refusal left its producer latch or poll armed");
    twfRequire(ls->tcp_pcb == NULL && ls->terminal_pending,
               "CTP retry refusal did not detach and publish the terminal line");
    twfRequire(state->terminal_lines[0] == fixture.line, "CTP terminal registry did not own the refused line");
    twfRequire(lineIsAlive(fixture.line), "CTP destroyed a borrowed normal line from the lwIP callback");
    tosRequireAcceptedRequest(1);
    ctpFixtureRequirePacketLineAlive(&fixture);

    line_t *line = fixture.line;
    lineRef(line);
    ctpDrainTerminalLinesOnCurrentWorker(fixture.ctp, 0);
    twfRequire(state->terminal_lines[0] == NULL, "CTP owner drain left the terminal registry populated");
    twfRequireEqualU32(fixture.owner_finish_calls, 1, "CTP owner drain did not finish the borrowed line once");
    twfRequire(! lineIsAlive(line), "CTP owner drain left the borrowed line logically alive");
    twfRequireLineStateZeroed(line, fixture.ctp, "CTP owner drain left line state alive");
    twfRequireEqualU32(twfLineRefCount(line), 1, "CTP owner drain leaked a line reference");
    lineUnref(line);
    fixture.line = NULL;

    ctpFixtureTeardown(&fixture);
}

static void refusalWithoutOrderlyHandoff(void *argument)
{
    ctp_fixture_t *fixture = argument;
    ctp_lstate_t  *ls      = lineGetState(fixture->line, fixture->ctp);
    g_submit_expectation   = kCtpSubmitControl;
    enterEngine();
    discard ctpTcpPollCallback(ls, ls->tcp_pcb);
    leaveEngine();
}

static void caseRefusalWithoutOrderlyHandoffAborts(void)
{
    twfSetCase("CTP terminal refusal aborts when orderly handoff is unavailable");
    ctp_fixture_t fixture;
    ctpFixtureSetup(&fixture);
    discard       ctpAttachTestPcb(&fixture, ctpTcpPcbUsed());
    ctp_lstate_t *ls     = lineGetState(fixture.line, fixture.ctp);
    ls->connected        = true;
    ls->write_blocked    = true;
    ls->write_poll_armed = true;
    tosResetProcessApi(false);
    tosRequireChildExit("CTP refused orderly handoff", refusalWithoutOrderlyHandoff, &fixture, kTosChildFallbackAbort);
    tosResetProcessApi(true);
    ctpCloseFixtureLine(&fixture);
    ctpFixtureTeardown(&fixture);
}

static void caseCreditedDeliveryRefusalTransfersBufferAndRetainsPbuf(void)
{
    twfSetCase("ConnectionToPackets credited TCP delivery refusal");
    tosResetProcessApi(true);

    ctp_fixture_t fixture;
    ctpFixtureSetup(&fixture);
    const uint32_t  pcb_baseline = ctpTcpPcbUsed();
    struct tcp_pcb *pcb          = ctpAttachTestPcb(&fixture, pcb_baseline);
    ctp_lstate_t   *ls           = lineGetState(fixture.line, fixture.ctp);

    enterEngine();
    struct pbuf *p = pbuf_alloc(PBUF_RAW, 37, PBUF_RAM);
    twfRequire(p != NULL, "lwIP could not allocate the CTP test pbuf");
    memorySet(p->payload, 0x5A, p->len);
    const u16_t initial_ref = p->ref;

    g_submit_expectation = kCtpSubmitBufferedDelivery;
    const err_t result   = ctpTcpRecvCallback(ls, pcb, p, ERR_OK);
    g_submit_expectation = kCtpSubmitNone;
    twfRequireEqualU32(ctpTcpPcbUsedLocked(),
                       pcb_baseline + 1U,
                       "CTP rejected delivery released the PCB before explicit flow cleanup");
    leaveEngine();

    twfRequire(result == ERR_MEM, "CTP buffered refusal did not ask lwIP to replay its pbuf");
    twfRequireEqualU32(g_schedule_calls, 1, "CTP buffered refusal submitted the wrong number of tasks");
    twfRequireEqualU32(g_buffer_settlements, 1, "CTP scheduler did not settle the transferred sbuf once");
    twfRequireEqualU32(ls->rx_uncredited, 0, "CTP advanced receive credit after rejected delivery");
    twfRequireEqualU32((uint32_t) p->ref, (uint32_t) initial_ref, "CTP consumed lwIP's replay pbuf on rejection");
    twfRequire(((const uint8_t *) p->payload)[0] == UINT8_C(0x5A), "CTP corrupted the retained replay pbuf");
    tosRequireNoProcessApiCall();
    ctpFixtureRequirePacketLineAlive(&fixture);

    enterEngine();
    twfRequireEqualU32((uint32_t) pbuf_free(p), 1, "CTP test pbuf did not release exactly once");
    discard ctpTcpAbortFlowLocked(fixture.ctp, ls);
    twfRequireEqualU32(ctpTcpPcbUsedLocked(), pcb_baseline, "CTP buffered-case cleanup leaked its TCP PCB");
    leaveEngine();

    ctpCloseFixtureLine(&fixture);
    twfRequireEqualU32(fixture.owner_finish_calls, 1, "CTP buffered-case owner did not receive one Finish");
    ctpFixtureTeardown(&fixture);
}

static void casePendingBudgetAllowsOneReadOfHeadroom(uint32_t pool_size)
{
    twfSetCase("CTP admits a 1 MiB delivery with pool-independent headroom and rejects bytes beyond bounded headroom");
    g_pool_size             = pool_size;
    const uint32_t headroom = 1024U * 1024U;
    ctp_fixture_t  fixture;
    ctpFixtureSetup(&fixture);
    ctp_tstate_t *ts      = tunnelGetState(fixture.ctp);
    ctp_lstate_t *ls      = lineGetState(fixture.line, fixture.ctp);
    ts->max_pending_bytes = 256 * 1024;
    sbuf_t *buf           = bufferpoolGetBestFit(fixture.env.pool, headroom, 0);
    sbufSetLength(buf, headroom);
    lineRef(fixture.line);
    ctpTunnelUpStreamPayload(fixture.ctp, fixture.line, buf);
    twfRequire(lineIsAlive(fixture.line) && ls->write_paused, "CTP rejected the delivery before Pause could act");
    twfRequire(bufferqueueGetBufLen(&ls->pending_queue) == headroom, "CTP lost the delivered payload");
    lineUnref(fixture.line);
    buf = bufferpoolGetBestFit(fixture.env.pool, ts->max_pending_bytes, 0);
    sbufSetLength(buf, ts->max_pending_bytes);
    ctpTunnelUpStreamPayload(fixture.ctp, fixture.line, buf);
    twfRequire(bufferqueueGetBufLen(&ls->pending_queue) == (size_t) ts->max_pending_bytes + headroom,
               "CTP did not admit the exact headroom boundary");
    buf = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(buf, 1);
    lineRef(fixture.line);
    ctpTunnelUpStreamPayload(fixture.ctp, fixture.line, buf);
    twfRequire(! lineIsAlive(fixture.line) && fixture.owner_finish_calls == 1,
               "CTP failed to close the flow exceeding its bounded headroom");
    lineUnref(fixture.line);
    fixture.line = NULL;
    ctpFixtureTeardown(&fixture);
    g_pool_size = 4096;
}

static void caseTerminalPayloadReentry(void)
{
    twfSetCase("CTP terminal reconciliation closes during payload continuation");
    tosResetProcessApi(true);
    ctp_fixture_t fixture;
    ctpFixtureSetup(&fixture);
    const uint32_t baseline = ctpTcpPcbUsed();
    discard        ctpAttachTestPcb(&fixture, baseline);
    ctp_lstate_t  *ls = lineGetState(fixture.line, fixture.ctp);
    enterEngine();
    twfRequire(ctpRequiredControlRefusedLocked(fixture.ctp, ls, "test refusal"), "producer not detached");
    leaveEngine();
    sbuf_t *buf = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(buf, 1);
    /* No test reference masks the source freeing the line in the nested Finish. */
    ctpTunnelUpStreamPayload(fixture.ctp, fixture.line, buf);
    twfRequireEqualU32(fixture.owner_finish_calls, 1, "terminal payload did not close once");
    fixture.line = NULL;
    twfRequireEqualU32(ctpTcpPcbUsed(), baseline, "terminal payload leaked PCB");
    ctpFixtureTeardown(&fixture);
}

static void caseStopOrdering(bool node_first)
{
    twfSetCase(node_first ? "CTP drains before borrowed-line source" : "source drains before CTP");
    ctp_fixture_t fixture;
    ctpFixtureSetup(&fixture);
    const uint32_t baseline = ctpTcpPcbUsed();
    discard        ctpAttachTestPcb(&fixture, baseline);
    ctp_lstate_t  *ls  = lineGetState(fixture.line, fixture.ctp);
    sbuf_t        *buf = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(buf, 19);
    twfRequire(bufferqueueTryPushBack(&ls->pending_queue, &buf), "pending setup failed");
    ctpTunnelOnQuiesceRequest(fixture.ctp, wwLifecycleProcessShutdown());
    if (node_first)
    {
        ctpTunnelOnWorkerStop(fixture.ctp, 0, wwLifecycleProcessShutdown());
        twfRequire(ls->tcp_pcb == NULL && ls->tunnel == fixture.ctp, "node drain lost borrowed state");
        twfRequire(bufferqueueGetBufLen(&ls->pending_queue) == 19, "node drain released source-owned pending lifetime");
        twfRequireEqualU32(ctpTcpPcbUsed(), baseline, "node drain retained PCB");
        twfRequire(lineIsAlive(fixture.line), "node drain destroyed borrowed line");
    }
    lineRef(fixture.line);
    ctpTunnelUpStreamFinish(fixture.ctp, fixture.line);
    twfRequire(fixture.owner_finish_calls == 0, "source Finish was reflected");
    twfRequireLineStateZeroed(fixture.line, fixture.ctp, "source Finish retained state");
    lineDestroy(fixture.line);
    lineUnref(fixture.line);
    fixture.line = NULL;
    if (! node_first)
        ctpTunnelOnWorkerStop(fixture.ctp, 0, wwLifecycleProcessShutdown());
    twfRequireEqualU32(ctpTcpPcbUsed(), baseline, "stop order retained PCB");
    ctpFixtureTeardown(&fixture);
}

/* Frozen O2 checks: normal 2 MiB snd_buf; 100 KiB FIFO head plus a
 * distinct follower; full flush, second-write ERR_MEM, and actual zero capacity. */
static uint8_t sendByte(uint32_t offset)
{
    return (uint8_t) ((offset * 19U) ^ (offset >> 8U));
}

static sbuf_t *sendBuffer(ctp_fixture_t *fixture, uint32_t offset, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetBestFit(fixture->env.pool, length, 0);
    sbufSetLength(buf, length);
    for (uint32_t i = 0; i < length; ++i)
        sbufGetMutablePtr(buf)[i] = sendByte(offset + i);
    return buf;
}

static void requireQueuedBytes(struct tcp_pcb *pcb, uint32_t expected)
{
    uint32_t offset = 0;
    for (struct tcp_seg *seg = pcb->unsent; seg != NULL; seg = seg->next)
    {
        uint8_t bytes[TCP_MSS];
        twfRequire(seg->len <= sizeof(bytes), "CTP queued an oversized segment");
        twfRequire(pbuf_copy_partial(seg->p, bytes, seg->len, seg->p->tot_len - seg->len) == seg->len,
                   "could not inspect CTP queued bytes");
        for (uint32_t i = 0; i < seg->len; ++i)
            twfRequire(bytes[i] == sendByte(offset + i), "CTP changed, duplicated or reordered FIFO bytes");
        offset += seg->len;
    }
    twfRequireEqualU32(offset, expected, "CTP admitted the wrong byte count");
}

static void caseScaledSendCapacity(unsigned mode)
{
    twfSetCase("CTP drains scaled TCP capacity, preserves refused prefix and resumes FIFO");
    enum
    {
        length = 100U * 1024U,
        later  = 3333U
    };
    ctp_fixture_t fixture;
    ctpFixtureSetup(&fixture);
    const uint32_t  baseline = ctpTcpPcbUsed();
    struct tcp_pcb *pcb      = ctpAttachTestPcb(&fixture, baseline);
    ctp_lstate_t   *ls       = lineGetState(fixture.line, fixture.ctp);
    ls->connected            = true;
    bufferqueuePushBack(&ls->pending_queue, sendBuffer(&fixture, 0, length));
    bufferqueuePushBack(&ls->pending_queue, sendBuffer(&fixture, length, later));
    enterEngine();
    twfRequire(pcb->snd_buf == 2U * 1024U * 1024U, "CTP test lost normal scaled send capacity");
    pcb->state       = ESTABLISHED;
    pcb->mss         = TCP_MSS;
    pcb->snd_wnd_max = TCP_WND;
    IP_ADDR4(&pcb->remote_ip, 192, 0, 2, 1);
    TCP_REG_ACTIVE(pcb);
    tcp_nagle_disable(pcb);
    if (mode == 2)
        pcb->snd_buf = 0;
    tcp_write_calls = tcp_output_calls = 0;
    tcp_write_fail_call                = mode == 1 ? 2 : 0;
    const ctp_flush_result_t result    = ctpFlushPendingLocked(ls);
    tcp_write_fail_call                = 0;
    const uint32_t admitted            = mode == 0 ? length + later : mode == 1 ? UINT16_MAX : 0;
    requireQueuedBytes(pcb, admitted);
    twfRequire(tcp_output_calls == (admitted != 0 ? 1U : 0U), "CTP did not output the successful prefix exactly once");
    if (mode == 0)
        twfRequire(result == kCtpFlushProgressed && ! ls->write_blocked && ! ls->write_poll_armed &&
                       bufferqueueGetBufCount(&ls->pending_queue) == 0 && tcp_write_calls == 3,
                   "CTP stopped solely at the 16-bit write boundary");
    else
    {
        twfRequire(result == kCtpFlushRetryable && ls->write_blocked && ls->write_poll_armed &&
                       bufferqueueGetBufCount(&ls->pending_queue) == 2,
                   "CTP lost a blocked FIFO entry");
        const sbuf_t *suffix = bufferqueueFront(&ls->pending_queue);
        twfRequire(sbufGetLength(suffix) == length - admitted, "CTP retained copied bytes or lost its suffix");
        const uint8_t *bytes = sbufGetRawPtr(suffix);
        for (uint32_t i = 0; i < length - admitted; ++i)
            twfRequire(bytes[i] == sendByte(admitted + i), "CTP shifted its refused suffix incorrectly");
        if (mode == 2)
            pcb->snd_buf = 2U * 1024U * 1024U;
        twfRequire(ctpFlushPendingLocked(ls) == kCtpFlushProgressed, "CTP retry did not drain available capacity");
        requireQueuedBytes(pcb, length + later);
        twfRequire(! ls->write_blocked && ! ls->write_poll_armed && bufferqueueGetBufCount(&ls->pending_queue) == 0,
                   "CTP retry retained pressure or queued storage");
    }
    leaveEngine();
    twfRequireNoLeakedBuffers();
    ctpCloseFixtureLine(&fixture);
    twfRequireEqualU32(ctpTcpPcbUsed(), baseline, "CTP scaled send test leaked its PCB");
    ctpFixtureTeardown(&fixture);
}

typedef struct credit_output_s
{
    unsigned attempts, acknowledgments;
    uint32_t acknowledgment;
    uint16_t window;
    bool     fail_once;
} credit_output_t;

static err_t recordCreditOutput(struct netif *netif, struct pbuf *packet, const ip4_addr_t *destination)
{
    discard          destination;
    credit_output_t *output = netif->state;
    uint8_t          header[40];
    twfRequire(wwLwipEngineCurrent() == g_fixture->engine, "CTP credit output escaped its owner engine");
    twfRequire(pbuf_copy_partial(packet, header, sizeof(header), 0) == sizeof(header),
               "CTP credit output omitted IPv4/TCP headers");
    if (header[33] == TCP_ACK)
    {
        ++output->attempts;
        if (output->fail_once)
        {
            output->fail_once = false;
            return ERR_IF;
        }
        ++output->acknowledgments;
        output->acknowledgment = GET_BE32(header + 28);
        output->window         = GET_BE16(header + 34);
    }
    return ERR_OK;
}

static err_t initCreditNetif(struct netif *netif)
{
    netif->name[0] = 'c';
    netif->name[1] = 'r';
    netif->mtu     = 1500;
    netif->output  = recordCreditOutput;
    return ERR_OK;
}

static void caseReceiveCredit(uint32_t amount, bool fail_once)
{
    twfSetCase("CTP Resume returns full-width credit in one successful wire ACK");
    ctp_fixture_t fixture;
    ctpFixtureSetup(&fixture);
    const uint32_t  baseline = ctpTcpPcbUsed();
    struct tcp_pcb *pcb      = ctpAttachTestPcb(&fixture, baseline);
    ctp_lstate_t   *ls       = lineGetState(fixture.line, fixture.ctp);
    credit_output_t output   = {0};
    struct netif    netif    = {0};
    enterEngine();
    ip4_addr_t local, mask, gateway;
    IP4_ADDR(&local, 192, 0, 2, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    IP4_ADDR(&gateway, 0, 0, 0, 0);
    twfRequire(netif_add(&netif, &local, &mask, &gateway, &output, initCreditNetif, ip_input) != NULL,
               "CTP credit fixture netif allocation failed");
    netif_set_up(&netif);
    netif_set_link_up(&netif);
    twfRequire(tcp_bind_netif(pcb, &netif) == ERR_OK, "CTP credit fixture netif binding failed");
    IP_ADDR4(&pcb->local_ip, 192, 0, 2, 1);
    IP_ADDR4(&pcb->remote_ip, 192, 0, 2, 2);
    pcb->local_port         = 8000;
    pcb->remote_port        = 40000;
    pcb->state              = ESTABLISHED;
    pcb->mss                = TCP_MSS;
    pcb->rcv_nxt            = UINT32_MAX - 1000U;
    pcb->rcv_wnd            = TCP_WND - amount;
    pcb->rcv_ann_wnd        = pcb->rcv_wnd;
    pcb->rcv_ann_right_edge = pcb->rcv_nxt + pcb->rcv_wnd;
    pcb->rcv_scale          = 7;
    tcp_set_flags(pcb, TF_WND_SCALE);
    TCP_REG_ACTIVE(pcb);
    tcp_ack_now(pcb);
    twfRequire(tcp_output(pcb) == ERR_OK && output.acknowledgments == 1,
               "CTP credit fixture failed to advertise its initial window");
    output              = (credit_output_t) {.fail_once = fail_once};
    ls->rx_uncredited   = amount;
    ls->read_paused_len = amount;
    ls->read_paused     = true;
    leaveEngine();

    ctpTunnelUpStreamResume(fixture.ctp, fixture.line);
    twfRequire(! ls->read_paused && ls->read_paused_len == 0 && ls->rx_uncredited == 0,
               "CTP Resume lost or duplicated returned receive credit");
    twfRequireEqualU32(pcb->rcv_wnd, TCP_WND, "CTP Resume did not restore the full receive window");
    twfRequireEqualU32(output.acknowledgments,
                       amount != 0 ? 1 : 0,
                       "CTP Resume emitted artificial window updates for one returned amount");
    twfRequireEqualU32(output.attempts,
                       amount != 0 ? 1U + fail_once : 0,
                       "CTP Resume did not retry a refused window update exactly once");
    if (amount != 0)
        twfRequire(output.acknowledgment == pcb->rcv_nxt && output.window == (TCP_WND >> 7),
                   "CTP Resume advertised an incomplete or incorrect final window");
    ctpCloseFixtureLine(&fixture);
    enterEngine();
    netif_remove(&netif);
    leaveEngine();
    twfRequireEqualU32(ctpTcpPcbUsed(), baseline, "CTP credit fixture leaked its PCB");
    ctpFixtureTeardown(&fixture);
}

int main(void)
{
    twfRequire(lwipTestRuntimeInitialize(), "failed to initialize the lwIP random runtime");
    wwLwipEngineSharedInit();

    const uint32_t headroom_pool_sizes[] = {4096, 65536, 131072, 4U * 1024U * 1024U};
    for (size_t i = 0; i < ARRAY_SIZE(headroom_pool_sizes); ++i)
        casePendingBudgetAllowsOneReadOfHeadroom(headroom_pool_sizes[i]);
    for (unsigned mode = 0; mode < 3; ++mode)
        caseScaledSendCapacity(mode);
    const uint32_t credit_amounts[] = {0, 16384, 131072, TCP_WND};
    for (size_t i = 0; i < ARRAY_SIZE(credit_amounts); ++i)
        caseReceiveCredit(credit_amounts[i], false);
    caseReceiveCredit(TCP_WND, true);
    caseTerminalPayloadReentry();
    caseStopOrdering(true);
    caseStopOrdering(false);
    caseOwnerRetryRefusalPublishesAndDrainsTerminalLine();
    caseRefusalWithoutOrderlyHandoffAborts();
    caseCreditedDeliveryRefusalTransfersBufferAndRetainsPbuf();

    wwLwipEngineSharedCleanup();
    lwipTestRuntimeCleanup();
    puts("connectiontopackets_schedule_rejection_test: all cases passed");
    return 0;
}
