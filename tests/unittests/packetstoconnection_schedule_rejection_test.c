/* Real PTC callbacks must reconcile refused scheduled work inside their owner
 * engine without losing credit, pbuf, line, or buffer ownership. */

#include "PacketsToConnection/structure.h"

#include "lwip_test_runtime.h"
#include "tunnel_orderly_shutdown_harness.h"

#include "lwip/stats.h"
#include "lwip/tcpip.h"

typedef enum ptc_submit_expectation_e
{
    kPtcSubmitNone = 0,
    kPtcSubmitControl,
    kPtcSubmitBufferedDelivery,
    kPtcSubmitErrorClose,
} ptc_submit_expectation_t;

typedef struct ptc_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *ptc;
    tunnel_t        *next;
    tunnel_chain_t  *chain;
    line_t          *line;
    line_t          *packet_line;
    ww_lwip_engine_t *engine;
} ptc_fixture_t;

static uint32_t                 g_pool_size = 4096;
static ptc_fixture_t           *g_fixture;
static ptc_submit_expectation_t g_submit_expectation;
static uint32_t                 g_schedule_calls;
static uint32_t                 g_buffer_settlements;
static ww_lwip_engine_t        *test_previous;
static unsigned                 tcp_write_calls, tcp_write_fail_call;
err_t                           __real_tcp_write(struct tcp_pcb *pcb, const void *data, u16_t length, u8_t flags);
err_t                           __wrap_tcp_write(struct tcp_pcb *pcb, const void *data, u16_t length, u8_t flags);
err_t                           __wrap_tcp_write(struct tcp_pcb *pcb, const void *data, u16_t length, u8_t flags)
{
    if (++tcp_write_calls == tcp_write_fail_call)
        return ERR_MEM;
    return __real_tcp_write(pcb, data, length, flags);
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

static uint32_t ptcTcpPcbUsedLocked(void)
{
    twfRequire(wwLwipEngineCurrent() == g_fixture->engine,
               "PacketsToConnection read PCB statistics without the owner engine");
    twfRequire(lwip_stats.memp[MEMP_TCP_PCB] != NULL, "lwIP did not publish TCP PCB pool statistics");
    return (uint32_t) lwip_stats.memp[MEMP_TCP_PCB]->used;
}

static uint32_t ptcTcpPcbUsed(void)
{
    enterEngine();
    const uint32_t used = ptcTcpPcbUsedLocked();
    leaveEngine();
    return used;
}

line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel)
{
    ptc_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL &&
                   (g_submit_expectation == kPtcSubmitControl || g_submit_expectation == kPtcSubmitErrorClose ||
                    g_submit_expectation == kPtcSubmitBufferedDelivery),
               "PacketsToConnection submitted an unexpected no-buffer task");
    twfRequire(line == fixture->line && t == fixture->ptc &&
                   (g_submit_expectation == kPtcSubmitBufferedDelivery ||
                    task == (g_submit_expectation == kPtcSubmitErrorClose ? ptcCloseLineTask : ptcWriteRetryTask)),
               "PacketsToConnection submitted the wrong control task");
    twfRequire(on_cancel == NULL, "PacketsToConnection requested lock-reentrant cancellation notification");
    twfRequire(wwLwipEngineCurrent() == g_fixture->engine,
               "PacketsToConnection control submission did not hold the owner engine");
    twfRequire(lineIsOnCurrentEventWorker(line),
               "PacketsToConnection control refusal did not originate from its owner engine");
    if (g_submit_expectation == kPtcSubmitBufferedDelivery)
    {
        ptc_lstate_t *ls = lineGetState(line, t);
        twfRequire(ls->rx_delivery != NULL, "PTC did not publish its owned receive buffer before scheduling");
    }

    lineRef(line);
    lineUnref(line);
    ++g_schedule_calls;
    return kLineTaskSubmitRejectedSettled;
}

line_task_submit_result_e __wrap_lineScheduleTaskWithBuf(line_t *const line, LineTaskFnWithBuf task, tunnel_t *t,
                                                         sbuf_t *buf, LineTaskCancelFn on_cancel)
{
    ptc_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL && g_submit_expectation == kPtcSubmitBufferedDelivery,
               "PacketsToConnection submitted an unexpected buffered task");
    twfRequire(line == fixture->line && t == fixture->ptc && task == ptcDeliverPayloadTask,
               "PacketsToConnection submitted the wrong buffered task");
    twfRequire(on_cancel == NULL, "PacketsToConnection requested lock-reentrant cancellation notification");
    twfRequire(wwLwipEngineCurrent() == g_fixture->engine,
               "PacketsToConnection buffered submission did not hold the owner engine");
    twfRequire(lineIsOnCurrentEventWorker(line),
               "PacketsToConnection buffered delivery did not originate from the line owner");

    lineRef(line);
    lineReuseBuffer(line, buf);
    lineUnref(line);
    ++g_schedule_calls;
    ++g_buffer_settlements;
    return kLineTaskSubmitRejectedSettled;
}

static void ptcFixtureSetup(ptc_fixture_t *fixture)
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

    fixture->ptc  = tunnelCreate(NULL, sizeof(ptc_tstate_t), sizeof(ptc_lstate_t));
    fixture->next = twfCreateNextTunnel(&fixture->trace);
    twfRequire(fixture->ptc != NULL, "failed to create the PacketsToConnection fixture tunnel");
    tunnelBind(fixture->ptc, fixture->next);

    fixture->chain = tunnelchainCreate(1);
    twfRequire(fixture->chain != NULL, "failed to create the PacketsToConnection fixture chain");
    fixture->chain->sum_line_state_size  = fixture->ptc->lstate_size;
    fixture->chain->contains_packet_node = true;
    tunnelchainFinalize(fixture->chain);
    twfRequire(fixture->chain->finalized, "failed to finalize the PacketsToConnection fixture chain");
    fixture->ptc->chain  = fixture->chain;
    fixture->packet_line = tunnelchainGetWorkerPacketLine(fixture->chain, 0);
    twfRequire(fixture->packet_line != NULL && lineIsAlive(fixture->packet_line),
               "PacketsToConnection fixture has no live packet line");

    ptc_tstate_t *state        = tunnelGetState(fixture->ptc);
    state->mtu                 = 1500;
    state->owned_worker_count  = 1;
    state->owned_lines         = memoryAllocateZero(sizeof(*state->owned_lines));
    state->max_pending_bytes   = kPtcDefaultMaxPendingBytes;
    state->max_pending_entries = kPtcMaxPendingEntries;
    twfRequire(state->owned_lines != NULL, "failed to allocate the PTC owner registry");
    mutexInit(&state->owned_lines_lock);
    atomic_init(&state->stopping, false);
    quiescenceGateInit(&state->output_gate);
    quiescenceGateInit(&state->next_gate);
    twfRequire(quiescenceGateOpen(&state->output_gate), "failed to open the PTC output gate");
    twfRequire(quiescenceGateOpen(&state->next_gate), "failed to open the PTC next-callback gate");

    fixture->line = lineCreate(tunnelchainGetLinePools(fixture->chain), 0);

    g_fixture            = fixture;
    g_submit_expectation = kPtcSubmitNone;
    g_schedule_calls     = 0;
    g_buffer_settlements = 0;
}

static void ptcFixtureRequirePacketLineAlive(const ptc_fixture_t *fixture)
{
    twfRequire(fixture->packet_line != NULL && lineIsAlive(fixture->packet_line),
               "PacketsToConnection destroyed the chain-owned packet line");
}

static void ptcFixtureTeardown(ptc_fixture_t *fixture)
{
    twfRequire(fixture->line == NULL, "PacketsToConnection fixture retained an owned normal line at teardown");
    ptcFixtureRequirePacketLineAlive(fixture);
    twfRequireNoLeakedBuffers();

    ptc_tstate_t *state = tunnelGetState(fixture->ptc);
    twfRequire(state->owned_lines[0] == NULL, "PacketsToConnection owner registry was not drained");
    mutexDestroy(&state->owned_lines_lock);
    memoryFree(state->owned_lines);
    state->owned_lines = NULL;

    tunnelchainDestroy(fixture->chain);
    tunnelDestroy(fixture->next);
    tunnelDestroy(fixture->ptc);
    g_fixture = NULL;
    wwLwipEngineDestroy(fixture->engine);
    twfWorkerEnvTeardown(&fixture->env);
}

static struct tcp_pcb *ptcAttachTestPcb(ptc_fixture_t *fixture, uint32_t pcb_baseline)
{
    enterEngine();
    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
    twfRequire(pcb != NULL, "lwIP could not allocate a PTC test PCB");
    twfRequireEqualU32(
        ptcTcpPcbUsedLocked(), pcb_baseline + 1U, "PTC test PCB allocation did not raise the used-count once");
    ptc_lstate_t *ls = lineGetState(fixture->line, fixture->ptc);
    twfRequire(ptcLinestateInitialize(ls, fixture->ptc, fixture->line, kPtcLineKindTcp, pcb),
               "failed to initialize the PTC line state");
    tcp_arg(pcb, ls);
    tcp_recv(pcb, lwipThreadPtcTcpRecvCallback);
    tcp_sent(pcb, ptcTcpSendCompleteCallback);
    tcp_poll(pcb, ptcTcpPollCallback, kPtcWritePollInterval);
    tcp_err(pcb, lwipThreadPtcTcpConnectionErrorCallback);
    leaveEngine();
    return pcb;
}

static void caseOwnerRetryRefusalPublishesAndDrainsOwnedLine(void)
{
    twfSetCase("PacketsToConnection owner retry refusal inside its engine");
    tosResetProcessApi(true);

    ptc_fixture_t fixture;
    ptcFixtureSetup(&fixture);
    const uint32_t  pcb_baseline = ptcTcpPcbUsed();
    struct tcp_pcb *pcb          = ptcAttachTestPcb(&fixture, pcb_baseline);
    ptc_lstate_t   *ls           = lineGetState(fixture.line, fixture.ptc);
    ls->write_poll_armed         = true;
    ls->next_init_sent           = true;

    g_submit_expectation = kPtcSubmitControl;
    enterEngine();
    const err_t result = ptcTcpPollCallback(ls, pcb);
    twfRequireEqualU32(ptcTcpPcbUsedLocked(), pcb_baseline, "PTC retry refusal leaked its detached TCP PCB");
    leaveEngine();
    g_submit_expectation = kPtcSubmitNone;

    ptc_tstate_t *state = tunnelGetState(fixture.ptc);
    twfRequire(result == ERR_ABRT, "PTC retry refusal did not report the aborted PCB");
    twfRequireEqualU32(g_schedule_calls, 1, "PTC retry refusal submitted the wrong number of tasks");
    twfRequire(! ls->write_retry_queued && ! ls->write_poll_armed,
               "PTC retry refusal left its producer latch or poll armed");
    twfRequire(ls->tcp_pcb == NULL && ls->terminal_required,
               "PTC retry refusal did not detach and publish the terminal owner line");
    twfRequire(state->owned_lines[0] == fixture.line, "PTC owner registry lost the refused line");
    twfRequire(lineIsAlive(fixture.line), "PTC destroyed its owned line inside the protocol callback");
    tosRequireAcceptedRequest(1);
    ptcFixtureRequirePacketLineAlive(&fixture);

    line_t *line = fixture.line;
    lineRef(line);
    ptcDrainTerminalLinesOnCurrentWorker(fixture.ptc, 0);
    twfRequire(state->owned_lines[0] == NULL, "PTC terminal owner drain left the line registered");
    twfRequireEqualU32(fixture.trace.next_finish, 1, "PTC terminal owner drain did not send one upstream Finish");
    twfRequire(! lineIsAlive(line), "PTC terminal owner drain left its normal line alive");
    twfRequireLineStateZeroed(line, fixture.ptc, "PTC terminal owner drain left line state alive");
    twfRequireEqualU32(twfLineRefCount(line), 1, "PTC terminal owner drain leaked a line reference");
    lineUnref(line);
    fixture.line = NULL;

    ptcFixtureTeardown(&fixture);
}

static void caseErrorClearsRouteBeforeTerminalClose(void)
{
    twfSetCase("PTC error clears its route before refused terminal reconciliation");
    tosResetProcessApi(true);
    ptc_fixture_t fixture;
    ptcFixtureSetup(&fixture);
    const uint32_t            baseline = ptcTcpPcbUsed();
    struct tcp_pcb           *pcb      = ptcAttachTestPcb(&fixture, baseline);
    ptc_lstate_t             *ls       = lineGetState(fixture.line, fixture.ptc);
    interface_route_context_t route    = {.engine = fixture.engine};
    ls->route_ctx                      = &route;
    g_submit_expectation               = kPtcSubmitErrorClose;
    enterEngine();
    tcp_abort(pcb);
    leaveEngine();
    g_submit_expectation = kPtcSubmitNone;
    twfRequire(ls->tcp_pcb == NULL && ls->route_ctx == NULL && ls->terminal_required,
               "PTC error retained a stack attachment");
    twfRequireEqualU32(ptcTcpPcbUsed(), baseline, "PTC error leaked its PCB");
    tosRequireAcceptedRequest(1);
    lineRef(fixture.line);
    ptcDrainTerminalLinesOnCurrentWorker(fixture.ptc, 0);
    twfRequire(! lineIsAlive(fixture.line), "PTC error left its owned line alive");
    twfRequireLineStateZeroed(fixture.line, fixture.ptc, "PTC error left line state alive");
    lineUnref(fixture.line);
    fixture.line = NULL;
    ptcFixtureTeardown(&fixture);
}

static void caseCreditedDeliveryRefusalRollsBackCreditAndRetainsPbuf(void)
{
    twfSetCase("PacketsToConnection credited TCP delivery refusal");
    tosResetProcessApi(true);

    ptc_fixture_t fixture;
    ptcFixtureSetup(&fixture);
    const uint32_t  pcb_baseline = ptcTcpPcbUsed();
    struct tcp_pcb *pcb          = ptcAttachTestPcb(&fixture, pcb_baseline);
    ptc_lstate_t   *ls           = lineGetState(fixture.line, fixture.ptc);

    enterEngine();
    struct pbuf *p = pbuf_alloc(PBUF_RAW, 41, PBUF_RAM);
    twfRequire(p != NULL, "lwIP could not allocate the PTC test pbuf");
    memorySet(p->payload, 0xA6, p->len);
    const u16_t initial_ref = p->ref;

    g_submit_expectation = kPtcSubmitBufferedDelivery;
    const err_t result   = lwipThreadPtcTcpRecvCallback(ls, pcb, p, ERR_OK);
    g_submit_expectation = kPtcSubmitNone;
    twfRequireEqualU32(ptcTcpPcbUsedLocked(),
                       pcb_baseline + 1U,
                       "PTC rejected delivery released the PCB before explicit owner cleanup");
    leaveEngine();

    twfRequire(result == ERR_MEM, "PTC buffered refusal did not ask lwIP to replay its pbuf");
    twfRequireEqualU32(g_schedule_calls, 1, "PTC buffered refusal submitted the wrong number of tasks");
    twfRequireEqualU32(g_buffer_settlements, 0, "PTC transferred its owned accumulator to the scheduler");
    twfRequire(ls->rx_delivery == NULL, "PTC did not settle its receive accumulator on submission refusal");
    twfRequireNoLeakedBuffers();
    twfRequireEqualU32(ls->rx_uncredited, 0, "PTC did not roll staged receive credit back exactly once");
    twfRequireEqualU32((uint32_t) p->ref, (uint32_t) initial_ref, "PTC consumed lwIP's replay pbuf on rejection");
    twfRequire(((const uint8_t *) p->payload)[0] == UINT8_C(0xA6), "PTC corrupted the retained replay pbuf");
    tosRequireNoProcessApiCall();
    ptcFixtureRequirePacketLineAlive(&fixture);

    enterEngine();
    twfRequireEqualU32((uint32_t) pbuf_free(p), 1, "PTC test pbuf did not release exactly once");
    leaveEngine();

    line_t *line = fixture.line;
    lineRef(line);
    ptcCloseLineForStop(fixture.ptc, line);
    twfRequireEqualU32(ptcTcpPcbUsed(), pcb_baseline, "PTC buffered-case owner cleanup leaked its TCP PCB");
    twfRequire(! lineIsAlive(line), "PTC buffered-case cleanup left its owned line alive");
    twfRequireLineStateZeroed(line, fixture.ptc, "PTC buffered-case cleanup left line state alive");
    twfRequireEqualU32(twfLineRefCount(line), 1, "PTC buffered-case cleanup leaked a line reference");
    lineUnref(line);
    fixture.line = NULL;

    ptcFixtureTeardown(&fixture);
}

static void casePendingBudgetAllowsOneReadOfHeadroom(uint32_t pool_size)
{
    twfSetCase("PTC admits a 1 MiB delivery with pool-independent headroom and rejects bytes beyond bounded headroom");
    g_pool_size             = pool_size;
    const uint32_t headroom = 1024U * 1024U;
    ptc_fixture_t fixture;
    ptcFixtureSetup(&fixture);
    const uint32_t pcb_baseline = ptcTcpPcbUsed();
    discard        ptcAttachTestPcb(&fixture, pcb_baseline);
    ptc_tstate_t  *ts     = tunnelGetState(fixture.ptc);
    ptc_lstate_t  *ls     = lineGetState(fixture.line, fixture.ptc);
    ts->max_pending_bytes = 256 * 1024;
    ls->next_init_sent    = true;
    ls->write_paused      = true;
    sbuf_t *buf           = bufferpoolGetBestFit(fixture.env.pool, headroom, 0);
    sbufSetLength(buf, headroom);
    lineRef(fixture.line);
    ptcTunnelDownStreamPayload(fixture.ptc, fixture.line, buf);
    twfRequire(lineIsAlive(fixture.line) && ls->pending_bytes == headroom,
               "PTC rejected the delivery before Pause could act");
    lineUnref(fixture.line);
    buf = bufferpoolGetBestFit(fixture.env.pool, ts->max_pending_bytes, 0);
    sbufSetLength(buf, ts->max_pending_bytes);
    ptcTunnelDownStreamPayload(fixture.ptc, fixture.line, buf);
    twfRequire(ls->pending_bytes == ts->max_pending_bytes + headroom, "PTC did not admit the exact headroom boundary");
    buf = bufferpoolGetSmallBuffer(fixture.env.pool);
    sbufSetLength(buf, 1);
    lineRef(fixture.line);
    ptcTunnelDownStreamPayload(fixture.ptc, fixture.line, buf);
    twfRequire(! lineIsAlive(fixture.line) && fixture.trace.next_finish == 1,
               "PTC failed to close the flow exceeding its bounded headroom");
    lineUnref(fixture.line);
    fixture.line = NULL;
    twfRequireEqualU32(ptcTcpPcbUsed(), pcb_baseline, "PTC overflow leaked its PCB");
    ptcFixtureTeardown(&fixture);
    g_pool_size = 4096;
}

static void caseResumeWaitsForDeliveryHeadroom(void)
{
    twfSetCase("PTC waits for ACK budget before resuming another large delivery");
    ptc_fixture_t fixture;
    ptcFixtureSetup(&fixture);
    const uint32_t baseline = ptcTcpPcbUsed();
    discard        ptcAttachTestPcb(&fixture, baseline);
    ptc_tstate_t  *ts = tunnelGetState(fixture.ptc);
    ptc_lstate_t  *ls = lineGetState(fixture.line, fixture.ptc);
    enterEngine();
    twfRequire(ptcReserveWriteSlots(ls), "PTC could not reserve a test ACK record");
    ptcAckQueuePushBack(ls, NULL, ts->max_pending_bytes + 1);
    ls->write_paused = true;
    twfRequire(ptcFlushWriteQueue(ls) == kPtcFlushRetryable && ls->write_paused,
               "PTC resumed with charged ACK bytes still using delivery headroom");
    leaveEngine();
    ptcResumeUpstreamTask(fixture.ptc, fixture.line);
    twfRequire(fixture.trace.len == 0, "a stale PTC Resume bypassed renewed pressure");
    enterEngine();
    sbuf_ack_t *ack = sbuf_ack_queue_t_front_mut(&ls->ack_queue);
    ack->written    = ack->total;
    ptcAckQueuePopFront(ls);
    twfRequire(ptcFlushWriteQueue(ls) == kPtcFlushComplete && ! ls->write_paused,
               "PTC failed to resume after ACK records released the budget");
    leaveEngine();
    ptcResumeUpstreamTask(fixture.ptc, fixture.line);
    twfRequire(stringCompare(fixture.trace.seq, "R") == 0,
               "PTC did not publish Resume after headroom became available");
    lineRef(fixture.line);
    ptcCloseLineForStop(fixture.ptc, fixture.line);
    twfRequire(! lineIsAlive(fixture.line), "PTC cleanup left its owned line alive");
    lineUnref(fixture.line);
    fixture.line = NULL;
    twfRequireEqualU32(ptcTcpPcbUsed(), baseline, "PTC budget test leaked its PCB");
    ptcFixtureTeardown(&fixture);
}

static uint8_t sendByte(uint32_t offset)
{
    return (uint8_t) ((offset * 19U) ^ (offset >> 8U));
}

static sbuf_t *sendBuffer(ptc_fixture_t *fixture, uint32_t offset, uint32_t length)
{
    sbuf_t *buf = bufferpoolGetBestFit(fixture->env.pool, length, 0);
    sbufSetLength(buf, length);
    uint8_t *bytes = sbufGetMutablePtr(buf);
    for (uint32_t i = 0; i < length; ++i)
        bytes[i] = sendByte(offset + i);
    return buf;
}

static void requireQueuedBytes(struct tcp_pcb *pcb, uint32_t expected)
{
    uint32_t offset = 0;
    for (struct tcp_seg *seg = pcb->unsent; seg != NULL; seg = seg->next)
    {
        uint8_t bytes[TCP_MSS];
        twfRequire(seg->len <= sizeof(bytes), "PTC queued an oversized TCP segment");
        twfRequire(pbuf_copy_partial(seg->p, bytes, seg->len, seg->p->tot_len - seg->len) == seg->len,
                   "could not inspect the queued TCP payload");
        for (uint32_t i = 0; i < seg->len; ++i)
            twfRequire(bytes[i] == sendByte(offset + i), "PTC changed, duplicated or reordered TCP bytes");
        offset += seg->len;
    }
    twfRequireEqualU32(offset, expected, "PTC admitted the wrong number of bytes into lwIP");
}

static void caseScaledSendCapacity(unsigned mode)
{
    twfSetCase("PTC fills scaled TCP capacity across 16-bit writes and preserves a refused suffix in FIFO order");
    const uint32_t length = 128U * 1024U;
    ptc_fixture_t  fixture;
    ptcFixtureSetup(&fixture);
    const uint32_t  baseline = ptcTcpPcbUsed();
    struct tcp_pcb *pcb      = ptcAttachTestPcb(&fixture, baseline);
    ptc_lstate_t   *ls       = lineGetState(fixture.line, fixture.ptc);
    enterEngine();
    pcb->state       = ESTABLISHED;
    pcb->mss         = TCP_MSS;
    pcb->snd_wnd_max = TCP_WND;
    /* No route: tcp_output leaves the real segmented bytes queued for inspection. */
    IP_ADDR4(&pcb->remote_ip, 192, 0, 2, 1);
    TCP_REG_ACTIVE(pcb);
    tcp_nagle_disable(pcb);
    if (mode == 2)
        pcb->snd_buf = 96U * 1024U;
    leaveEngine();
    ls->write_paused    = mode == 1;
    tcp_write_calls     = 0;
    tcp_write_fail_call = mode == 3 ? 2 : 0;
    ptcTunnelDownStreamPayload(fixture.ptc, fixture.line, sendBuffer(&fixture, 0, length));
    tcp_write_fail_call = 0;

    const uint32_t admitted = mode == 0 ? length : mode == 2 ? 96U * 1024U : mode == 3 ? UINT16_MAX : 0;
    enterEngine();
    requireQueuedBytes(pcb, admitted);
    leaveEngine();
    twfRequireEqualU32(ls->pending_bytes, length, "partial admission changed the ACK record total");
    twfRequireEqualU32((uint32_t) sbuf_ack_queue_t_size(&ls->ack_queue), 1, "PTC split one payload's ACK record");
    if (mode == 0)
    {
        twfRequire(! ls->write_paused && ! ls->write_poll_armed && fixture.trace.len == 0,
                   "PTC paused despite available scaled TCP capacity");
        twfRequire(sbuf_ack_queue_t_front(&ls->ack_queue)->buf == NULL, "fully copied payload retained its sbuf");
    }
    else
    {
        twfRequire(ls->write_paused && bufferqueueGetBufCount(&ls->pause_queue) == 1, "PTC lost the refused suffix");
        const sbuf_t *suffix = sbuf_ack_queue_t_front(&ls->ack_queue)->buf;
        twfRequire(suffix != NULL && sbufGetLength(suffix) == length - admitted,
                   "PTC retained already copied bytes or lost its suffix");
        const uint8_t *bytes = sbufGetRawPtr(suffix);
        for (uint32_t i = 0; i < length - admitted; ++i)
            twfRequire(bytes[i] == sendByte(admitted + i), "PTC shifted the refused suffix incorrectly");
        /* A delivery already in flight must remain behind the older suffix. */
        const uint32_t later = 3333;
        ptcTunnelDownStreamPayload(fixture.ptc, fixture.line, sendBuffer(&fixture, length, later));
        enterEngine();
        if (mode == 2)
            pcb->snd_buf += length;
        twfRequire(ptcFlushWriteQueue(ls) == kPtcFlushComplete, "PTC stopped draining at the 16-bit API boundary");
        requireQueuedBytes(pcb, length + later);
        leaveEngine();
        twfRequire(! ls->write_paused && ! ls->write_poll_armed && bufferqueueGetBufCount(&ls->pause_queue) == 0,
                   "PTC retained pause state after admitting the complete FIFO");
        twfRequireEqualU32(ls->pending_bytes, length + later, "draining changed pending acknowledgement totals");
    }
    twfRequireNoLeakedBuffers();
    lineRef(fixture.line);
    ptcCloseLineForStop(fixture.ptc, fixture.line);
    twfRequire(! lineIsAlive(fixture.line), "PTC send test cleanup left its owned line alive");
    lineUnref(fixture.line);
    fixture.line = NULL;
    twfRequireEqualU32(ptcTcpPcbUsed(), baseline, "PTC send test leaked its PCB");
    ptcFixtureTeardown(&fixture);
}

static bool                         output_probe, output_refuse, output_inline;
static unsigned                     output_messages, output_deliveries, output_allocations;
static sbuf_t                      *output_buffer;
static WorkerMessageCallback        output_callback;
static WorkerMessageCleanupCallback output_cleanup;
static uint8_t                      output_bytes[257];

void *__real_memoryAllocate(size_t size);
void *__wrap_memoryAllocate(size_t size);
void *__wrap_memoryAllocate(size_t size)
{
    if (output_probe)
        ++output_allocations;
    return __real_memoryAllocate(size);
}
worker_message_submit_result_e __real_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *a, void *b, void *c);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *a, void *b, void *c);
worker_message_submit_result_e __wrap_sendWorkerMessageForceQueueWithCleanup(wid_t wid, WorkerMessageCallback callback,
                                                                             WorkerMessageCleanupCallback cleanup,
                                                                             void *a, void *b, void *c)
{
    if (! output_probe)
        return __real_sendWorkerMessageForceQueueWithCleanup(wid, callback, cleanup, a, b, c);
    twfRequire(wid == 0 && a == g_fixture->ptc && c == NULL, "wrong packet message route");
    twfRequire(g_twf_buffers.live_count == 1 && b == g_twf_buffers.live[0], "message did not own final sbuf");
    output_buffer   = b;
    output_callback = callback;
    output_cleanup  = cleanup;
    ++output_messages;
    if (output_refuse)
    {
        cleanup(a, b, c, kWorkerMessageCancelAdmissionClosed);
        return kWorkerMessageSubmitRejectedCleanupRan;
    }
    return kWorkerMessageSubmitAccepted;
}

static void outputSink(tunnel_t *t, line_t *line, sbuf_t *buffer)
{
    discard t;
    twfRequire(output_inline || wwLwipEngineCurrent() == NULL, "arbitrary neighbour entered active engine");
    twfRequire(line == g_fixture->packet_line && g_twf_buffers.live_count == 1 && buffer == g_twf_buffers.live[0],
               "delivery changed sbuf identity");
    if (! output_inline)
        twfRequire(buffer == output_buffer, "queue delivery copied output buffer");
    twfRequire(sbufGetLength(buffer) == sizeof(output_bytes) &&
                   memoryEqual(sbufGetRawPtr(buffer), output_bytes, sizeof(output_bytes)),
               "pbuf bytes changed");
    twfRequire(sbufGetLeftCapacity(buffer) >= 96, "packet output lost chain padding");
    ++output_deliveries;
    lineReuseBuffer(line, buffer);
}

static void *cancelPacketOnForeignThread(void *argument)
{
    output_cleanup(argument, output_buffer, NULL, kWorkerMessageCancelTeardown);
    return NULL;
}

static void casePacketOutput(bool certified, unsigned settlement, bool chained)
{
    twfSetCase("PTC final output sbuf and certified inline dispatch");
    ptc_fixture_t fixture;
    ptcFixtureSetup(&fixture);
    bufferpoolUpdateAllocationPaddings(fixture.env.pool, 96, 96, 96, 96);
    /* Warm allocation before the measured output callback. */
    lineReuseBuffer(fixture.packet_line, bufferpoolGetBestFit(fixture.env.pool, 257, 96));
    twfBufferLedgerReset();
    node_t    sink_node = {.layer_group = kNodeLayer3,
                           .flags       = certified ? kNodeFlagPacketPayloadEnqueueOnly : kNodeFlagNone};
    tunnel_t *sink      = tunnelCreate(&sink_node, 0, 0);
    sink->chain         = fixture.chain;
    sink->fnPayloadD    = outputSink;
    tunnelBind(sink, fixture.ptc);
    if (certified)
    {
        twfRequire(! packettunnelCanEnqueueDownstreamInline(fixture.ptc, fixture.line), "normal line inlined");
        sink->next = NULL;
        twfRequire(! packettunnelCanEnqueueDownstreamInline(fixture.ptc, fixture.packet_line),
                   "one-sided edge inlined");
        sink->next            = fixture.ptc;
        sink_node.layer_group = kNodeLayer4;
        twfRequire(! packettunnelCanEnqueueDownstreamInline(fixture.ptc, fixture.packet_line), "stream edge inlined");
        sink_node.layer_group = kNodeLayer3;
        testWorkerUnbindWID();
        twfRequire(! packettunnelCanEnqueueDownstreamInline(fixture.ptc, fixture.packet_line),
                   "foreign worker inlined");
        testWorkerBindWID(0);
    }
    interface_route_context_t route = {.tunnel = fixture.ptc, .engine = fixture.engine, .packet_wid = 0};
    struct netif              netif = {.state = &route};
    for (unsigned i = 0; i < sizeof(output_bytes); ++i)
        output_bytes[i] = (uint8_t) i;
    struct pbuf following = {.payload = (void *) 1, .len = 100, .tot_len = 100};
    struct pbuf tail      = {.payload = output_bytes + 17, .len = 240, .tot_len = 240, .next = &following};
    struct pbuf empty     = {.payload = NULL, .len = 0, .tot_len = 240, .next = &tail};
    struct pbuf head      = {
             .payload = output_bytes, .len = chained ? 17 : 257, .tot_len = 257, .next = chained ? &empty : &following};
    output_messages = output_deliveries = output_allocations = 0;
    output_inline                                            = certified;
    output_refuse                                            = settlement == 1;
    output_probe                                             = true;
    enterEngine();
    err_t result = ptcNetifOutput(&netif, &head, NULL);
    leaveEngine();
    output_probe = false;
    twfRequire(result == (output_refuse && ! certified ? ERR_MEM : ERR_OK), "packet output result");
    twfRequire(output_allocations == 0 && g_twf_buffers.total_acquired == 1, "intermediate allocation retained");
    twfRequire(output_messages == (certified ? 0 : 1), "wrong output message count");
    if (! certified && ! output_refuse)
    {
        if (settlement == 2 || settlement == 3)
        {
            if (settlement == 3)
            {
                pthread_t thread;
                twfRequire(pthread_create(&thread, NULL, cancelPacketOnForeignThread, fixture.ptc) == 0,
                           "foreign cancellation thread creation");
                twfRequire(pthread_join(thread, NULL) == 0, "foreign cancellation thread join");
            }
            else
                output_cleanup(fixture.ptc, output_buffer, NULL, kWorkerMessageCancelQuiesced);
        }
        else
        {
            if (settlement == 4)
                quiescenceGateClose(&((ptc_tstate_t *) tunnelGetState(fixture.ptc))->output_gate);
            output_callback(&fixture.env.worker, fixture.ptc, output_buffer, NULL);
        }
    }
    twfRequire(output_deliveries == ((certified || settlement == 0) ? 1 : 0), "wrong delivery count");
    twfRequireNoLeakedBuffers();
    ptc_tstate_t *state = tunnelGetState(fixture.ptc);
    quiescenceGateClose(&state->output_gate);
    enterEngine();
    twfRequire(ptcNetifOutput(&netif, &head, NULL) == ERR_IF, "closed output gate accepted work");
    leaveEngine();
    twfRequire(g_twf_buffers.total_acquired == 1, "closed gate allocated a buffer");
    lineDestroy(fixture.line);
    fixture.line = NULL;
    tunnelDestroy(sink);
    ptcFixtureTeardown(&fixture);
}

int main(void)
{
    twfRequire(lwipTestRuntimeInitialize(), "failed to initialize the lwIP random runtime");
    wwLwipEngineSharedInit();
    ptcRxWrapperPoolInitializeOnce();

    for (unsigned chained = 0; chained < 2; ++chained)
    {
        casePacketOutput(true, 0, chained);
        for (unsigned settlement = 0; settlement < 5; ++settlement)
            casePacketOutput(false, settlement, chained);
    }

    const uint32_t headroom_pool_sizes[] = {4096, 65536, 131072, 4U * 1024U * 1024U};
    for (size_t i = 0; i < ARRAY_SIZE(headroom_pool_sizes); ++i)
        casePendingBudgetAllowsOneReadOfHeadroom(headroom_pool_sizes[i]);
    caseResumeWaitsForDeliveryHeadroom();
    for (unsigned mode = 0; mode < 4; ++mode)
        caseScaledSendCapacity(mode);
    caseOwnerRetryRefusalPublishesAndDrainsOwnedLine();
    caseErrorClearsRouteBeforeTerminalClose();
    caseCreditedDeliveryRefusalRollsBackCreditAndRetainsPbuf();

    wwLwipEngineSharedCleanup();
    lwipTestRuntimeCleanup();
    puts("packetstoconnection_schedule_rejection_test: all cases passed");
    return 0;
}
