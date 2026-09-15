/* Real CTP lwIP callbacks must reconcile refused owner work without re-locking
 * the already-held core mutex or losing line/buffer ownership. */

#include "ConnectionToPackets/structure.h"

#include "lwip_test_runtime.h"
#include "tunnel_orderly_shutdown_harness.h"

#include "lwip/stats.h"
#include "lwip/tcpip.h"

typedef enum ctp_submit_expectation_e
{
    kCtpSubmitNone = 0,
    kCtpSubmitControl,
    kCtpSubmitBufferedDelivery,
} ctp_submit_expectation_t;

typedef struct ctp_fixture_s
{
    twf_worker_env_t env;
    twf_trace_t      trace;
    tunnel_t        *prev;
    tunnel_t        *ctp;
    tunnel_chain_t  *chain;
    line_t          *line;
    line_t          *packet_line;
    uint32_t         owner_finish_calls;
} ctp_fixture_t;

static ctp_fixture_t           *g_fixture;
static ctp_submit_expectation_t g_submit_expectation;
static uint32_t                 g_schedule_calls;
static uint32_t                 g_buffer_settlements;
static thread_local uint32_t    g_core_lock_depth;

void                      __real_sys_lock_tcpip_core(void);
void                      __real_sys_unlock_tcpip_core(void);
void                      __wrap_sys_lock_tcpip_core(void);
void                      __wrap_sys_unlock_tcpip_core(void);
line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel);
line_task_submit_result_e __wrap_lineScheduleTaskWithBuf(line_t *const line, LineTaskFnWithBuf task, tunnel_t *t,
                                                         sbuf_t *buf, LineTaskCancelFn on_cancel);

void __wrap_sys_lock_tcpip_core(void)
{
    twfRequire(g_core_lock_depth == 0, "ConnectionToPackets recursively acquired the lwIP core lock");
    __real_sys_lock_tcpip_core();
    g_core_lock_depth = 1;
}

void __wrap_sys_unlock_tcpip_core(void)
{
    twfRequire(g_core_lock_depth == 1, "ConnectionToPackets released an unheld lwIP core lock");
    g_core_lock_depth = 0;
    __real_sys_unlock_tcpip_core();
}

static uint32_t ctpTcpPcbUsedLocked(void)
{
    twfRequire(g_core_lock_depth == 1, "ConnectionToPackets read PCB statistics without the lwIP core lock");
    twfRequire(lwip_stats.memp[MEMP_TCP_PCB] != NULL, "lwIP did not publish TCP PCB pool statistics");
    return (uint32_t) lwip_stats.memp[MEMP_TCP_PCB]->used;
}

static uint32_t ctpTcpPcbUsed(void)
{
    LOCK_TCPIP_CORE();
    const uint32_t used = ctpTcpPcbUsedLocked();
    UNLOCK_TCPIP_CORE();
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
    twfRequire(g_core_lock_depth == 1, "ConnectionToPackets control submission did not hold the lwIP core lock");
    twfRequire(! lineIsOnCurrentEventWorker(line),
               "ConnectionToPackets control refusal did not originate from a foreign lwIP context");

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
    twfRequire(g_core_lock_depth == 1, "ConnectionToPackets buffered submission did not hold the lwIP core lock");
    twfRequire(lineIsOnCurrentEventWorker(line),
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
    twfWorkerEnvSetup(&fixture->env, 4096, 0);

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
    twfRequire(
        ctpLinestateInitialize(lineGetState(fixture->line, fixture->ctp), fixture->ctp, fixture->line, kCtpLineKindTcp),
        "failed to initialize the CTP line state");

    g_fixture            = fixture;
    g_submit_expectation = kCtpSubmitNone;
    g_schedule_calls     = 0;
    g_buffer_settlements = 0;
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
    memoryFree(state->terminal_lines);
    state->terminal_lines = NULL;

    tunnelchainDestroy(fixture->chain);
    tunnelDestroy(fixture->ctp);
    tunnelDestroy(fixture->prev);
    g_fixture = NULL;
    twfWorkerEnvTeardown(&fixture->env);
}

static struct tcp_pcb *ctpAttachTestPcb(ctp_fixture_t *fixture, uint32_t pcb_baseline)
{
    ctp_lstate_t *ls = lineGetState(fixture->line, fixture->ctp);

    LOCK_TCPIP_CORE();
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
    UNLOCK_TCPIP_CORE();
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

static void caseForeignRetryRefusalPublishesAndDrainsTerminalLine(void)
{
    twfSetCase("ConnectionToPackets foreign retry refusal under the lwIP core lock");
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
    testWorkerUnbindWID();
    LOCK_TCPIP_CORE();
    const err_t result = ctpTcpPollCallback(ls, pcb);
    twfRequireEqualU32(ctpTcpPcbUsedLocked(), pcb_baseline, "CTP retry refusal leaked its detached TCP PCB");
    UNLOCK_TCPIP_CORE();
    testWorkerBindWID(0);
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

static void caseCreditedDeliveryRefusalTransfersBufferAndRetainsPbuf(void)
{
    twfSetCase("ConnectionToPackets credited TCP delivery refusal");
    tosResetProcessApi(true);

    ctp_fixture_t fixture;
    ctpFixtureSetup(&fixture);
    const uint32_t  pcb_baseline = ctpTcpPcbUsed();
    struct tcp_pcb *pcb          = ctpAttachTestPcb(&fixture, pcb_baseline);
    ctp_lstate_t   *ls           = lineGetState(fixture.line, fixture.ctp);

    LOCK_TCPIP_CORE();
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
    UNLOCK_TCPIP_CORE();

    twfRequire(result == ERR_MEM, "CTP buffered refusal did not ask lwIP to replay its pbuf");
    twfRequireEqualU32(g_schedule_calls, 1, "CTP buffered refusal submitted the wrong number of tasks");
    twfRequireEqualU32(g_buffer_settlements, 1, "CTP scheduler did not settle the transferred sbuf once");
    twfRequireEqualU32(ls->rx_uncredited, 0, "CTP advanced receive credit after rejected delivery");
    twfRequireEqualU32((uint32_t) p->ref, (uint32_t) initial_ref, "CTP consumed lwIP's replay pbuf on rejection");
    twfRequire(((const uint8_t *) p->payload)[0] == UINT8_C(0x5A), "CTP corrupted the retained replay pbuf");
    tosRequireNoProcessApiCall();
    ctpFixtureRequirePacketLineAlive(&fixture);

    LOCK_TCPIP_CORE();
    twfRequireEqualU32((uint32_t) pbuf_free(p), 1, "CTP test pbuf did not release exactly once");
    discard ctpTcpAbortFlowLocked(fixture.ctp, ls);
    twfRequireEqualU32(ctpTcpPcbUsedLocked(), pcb_baseline, "CTP buffered-case cleanup leaked its TCP PCB");
    UNLOCK_TCPIP_CORE();

    ctpCloseFixtureLine(&fixture);
    twfRequireEqualU32(fixture.owner_finish_calls, 1, "CTP buffered-case owner did not receive one Finish");
    ctpFixtureTeardown(&fixture);
}

static atomic_bool g_lwip_initialized;

static void ctpLwipInitialized(void *argument)
{
    discard argument;
    frandInit();
    atomicStoreExplicit(&g_lwip_initialized, true, memory_order_release);
}

int main(void)
{
    twfRequire(lwipTestRuntimeInitialize(), "failed to initialize the lwIP random runtime");
    atomic_init(&g_lwip_initialized, false);
    tcpip_init(ctpLwipInitialized, NULL);
    while (! atomicLoadExplicit(&g_lwip_initialized, memory_order_acquire))
    {
        YIELD_THREAD();
    }

    caseForeignRetryRefusalPublishesAndDrainsTerminalLine();
    caseCreditedDeliveryRefusalTransfersBufferAndRetainsPbuf();

    twfRequire(wwLwipShutdown(), "failed to stop the CTP fixture lwIP thread");
    lwipTestRuntimeCleanup();
    puts("connectiontopackets_schedule_rejection_test: all cases passed");
    return 0;
}
