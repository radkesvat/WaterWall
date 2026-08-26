/* Real PTC lwIP callbacks must reconcile refused owner work without re-locking
 * the already-held core mutex or losing credit, pbuf, line, or buffer ownership. */

#include "PacketsToConnection/structure.h"

#include "tunnel_orderly_shutdown_harness.h"

#include "lwip/stats.h"
#include "lwip/tcpip.h"

typedef enum ptc_submit_expectation_e
{
    kPtcSubmitNone = 0,
    kPtcSubmitControl,
    kPtcSubmitBufferedDelivery,
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
} ptc_fixture_t;

static ptc_fixture_t           *g_fixture;
static ptc_submit_expectation_t g_submit_expectation;
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
    twfRequire(g_core_lock_depth == 0, "PacketsToConnection recursively acquired the lwIP core lock");
    __real_sys_lock_tcpip_core();
    g_core_lock_depth = 1;
}

void __wrap_sys_unlock_tcpip_core(void)
{
    twfRequire(g_core_lock_depth == 1, "PacketsToConnection released an unheld lwIP core lock");
    g_core_lock_depth = 0;
    __real_sys_unlock_tcpip_core();
}

static uint32_t ptcTcpPcbUsedLocked(void)
{
    twfRequire(g_core_lock_depth == 1, "PacketsToConnection read PCB statistics without the lwIP core lock");
    twfRequire(lwip_stats.memp[MEMP_TCP_PCB] != NULL, "lwIP did not publish TCP PCB pool statistics");
    return (uint32_t) lwip_stats.memp[MEMP_TCP_PCB]->used;
}

static uint32_t ptcTcpPcbUsed(void)
{
    LOCK_TCPIP_CORE();
    const uint32_t used = ptcTcpPcbUsedLocked();
    UNLOCK_TCPIP_CORE();
    return used;
}

line_task_submit_result_e __wrap_lineScheduleTask(line_t *const line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn on_cancel)
{
    ptc_fixture_t *fixture = g_fixture;
    twfRequire(fixture != NULL && g_submit_expectation == kPtcSubmitControl,
               "PacketsToConnection submitted an unexpected no-buffer task");
    twfRequire(line == fixture->line && t == fixture->ptc && task == ptcWriteRetryTask,
               "PacketsToConnection submitted the wrong control task");
    twfRequire(on_cancel == NULL, "PacketsToConnection requested lock-reentrant cancellation notification");
    twfRequire(g_core_lock_depth == 1, "PacketsToConnection control submission did not hold the lwIP core lock");
    twfRequire(! lineIsOnCurrentEventWorker(line),
               "PacketsToConnection control refusal did not originate from a foreign lwIP context");

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
    twfRequire(g_core_lock_depth == 1, "PacketsToConnection buffered submission did not hold the lwIP core lock");
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
    twfWorkerEnvSetup(&fixture->env, 4096, 0);

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
    twfWorkerEnvTeardown(&fixture->env);
}

static struct tcp_pcb *ptcAttachTestPcb(ptc_fixture_t *fixture, uint32_t pcb_baseline)
{
    LOCK_TCPIP_CORE();
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
    UNLOCK_TCPIP_CORE();
    return pcb;
}

static void caseForeignRetryRefusalPublishesAndDrainsOwnedLine(void)
{
    twfSetCase("PacketsToConnection foreign retry refusal under the lwIP core lock");
    tosResetProcessApi(true);

    ptc_fixture_t fixture;
    ptcFixtureSetup(&fixture);
    const uint32_t  pcb_baseline = ptcTcpPcbUsed();
    struct tcp_pcb *pcb          = ptcAttachTestPcb(&fixture, pcb_baseline);
    ptc_lstate_t   *ls           = lineGetState(fixture.line, fixture.ptc);
    ls->write_poll_armed         = true;
    ls->next_init_sent           = true;

    g_submit_expectation = kPtcSubmitControl;
    testWorkerUnbindWID();
    LOCK_TCPIP_CORE();
    const err_t result = ptcTcpPollCallback(ls, pcb);
    twfRequireEqualU32(ptcTcpPcbUsedLocked(), pcb_baseline, "PTC retry refusal leaked its detached TCP PCB");
    UNLOCK_TCPIP_CORE();
    testWorkerBindWID(0);
    g_submit_expectation = kPtcSubmitNone;

    ptc_tstate_t *state = tunnelGetState(fixture.ptc);
    twfRequire(result == ERR_ABRT, "PTC retry refusal did not report the aborted PCB");
    twfRequireEqualU32(g_schedule_calls, 1, "PTC retry refusal submitted the wrong number of tasks");
    twfRequire(! ls->write_retry_queued && ! ls->write_poll_armed,
               "PTC retry refusal left its producer latch or poll armed");
    twfRequire(ls->tcp_pcb == NULL && ls->terminal_required,
               "PTC retry refusal did not detach and publish the terminal owner line");
    twfRequire(state->owned_lines[0] == fixture.line, "PTC owner registry lost the refused line");
    twfRequire(lineIsAlive(fixture.line), "PTC destroyed its owned line from the foreign lwIP callback");
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

static void caseCreditedDeliveryRefusalRollsBackCreditAndRetainsPbuf(void)
{
    twfSetCase("PacketsToConnection credited TCP delivery refusal");
    tosResetProcessApi(true);

    ptc_fixture_t fixture;
    ptcFixtureSetup(&fixture);
    const uint32_t  pcb_baseline = ptcTcpPcbUsed();
    struct tcp_pcb *pcb          = ptcAttachTestPcb(&fixture, pcb_baseline);
    ptc_lstate_t   *ls           = lineGetState(fixture.line, fixture.ptc);

    LOCK_TCPIP_CORE();
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
    UNLOCK_TCPIP_CORE();

    twfRequire(result == ERR_MEM, "PTC buffered refusal did not ask lwIP to replay its pbuf");
    twfRequireEqualU32(g_schedule_calls, 1, "PTC buffered refusal submitted the wrong number of tasks");
    twfRequireEqualU32(g_buffer_settlements, 1, "PTC scheduler did not settle the transferred sbuf once");
    twfRequireEqualU32(ls->rx_uncredited, 0, "PTC did not roll staged receive credit back exactly once");
    twfRequireEqualU32((uint32_t) p->ref, (uint32_t) initial_ref, "PTC consumed lwIP's replay pbuf on rejection");
    twfRequire(((const uint8_t *) p->payload)[0] == UINT8_C(0xA6), "PTC corrupted the retained replay pbuf");
    tosRequireNoProcessApiCall();
    ptcFixtureRequirePacketLineAlive(&fixture);

    LOCK_TCPIP_CORE();
    twfRequireEqualU32((uint32_t) pbuf_free(p), 1, "PTC test pbuf did not release exactly once");
    UNLOCK_TCPIP_CORE();

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

static atomic_bool g_lwip_initialized;

static void ptcLwipInitialized(void *argument)
{
    discard argument;
    atomicStoreExplicit(&g_lwip_initialized, true, memory_order_release);
}

int main(void)
{
    atomic_init(&g_lwip_initialized, false);
    tcpip_init(ptcLwipInitialized, NULL);
    while (! atomicLoadExplicit(&g_lwip_initialized, memory_order_acquire))
    {
        YIELD_THREAD();
    }
    ptcRxWrapperPoolInitializeOnce();

    caseForeignRetryRefusalPublishesAndDrainsOwnedLine();
    caseCreditedDeliveryRefusalRollsBackCreditAndRetainsPbuf();

    twfRequire(tcpip_shutdown(NULL, NULL) == ERR_OK, "failed to stop the PTC fixture lwIP thread");
    puts("packetstoconnection_schedule_rejection_test: all cases passed");
    return 0;
}
