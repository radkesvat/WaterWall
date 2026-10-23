/*
 * Covers: real bridge owner callbacks refusing required queued work during shutdown.
 * Setup: two runtime event workers, production worker-message admission and shutdown
 * arbitration, real PCB callbacks, and a bounded linker pause before the real scheduler.
 * Checks: accepted success stays 0, an initial terminal refusal selects 1, and owner
 * drain releases each PCB, retained buffer, registry obligation and normal line once.
 * CTest: waterwall.connectiontopackets_shutdown_refusal_unit;
 * waterwall.packetstoconnection_shutdown_refusal_unit
 */
#if TEST_CONNECTION_TO_PACKETS
#include "ConnectionToPackets/structure.h"
#else
#include "PacketsToConnection/structure.h"
#endif
#include "engine_runtime.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/stats.h"
#include "test_assert.h"
#include "worker_messages.h"

#include <errno.h>
#include <pthread.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_QUICK_EXIT, condition, message)

enum
{
    kOwner          = 1,
    kTimeoutSeconds = 10
};

static tunnel_t       *bridge, *source, *next;
static tunnel_chain_t *chain;
static line_t         *normal_line;
static sbuf_t         *retained_buffer;
static pthread_mutex_t pause_mutex     = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  pause_condition = PTHREAD_COND_INITIALIZER;
static bool            paused, released;
static atomic_bool     callback_returned;
static unsigned        submissions, buffer_releases, owner_settlements, neighbor_finishes;
static uint32_t        pcb_baseline;

static struct timespec deadline(void)
{
    struct timespec result;
    require(clock_gettime(CLOCK_REALTIME, &result) == 0, "clock_gettime failed");
    result.tv_sec += kTimeoutSeconds;
    return result;
}

static void waitFor(bool *condition, const char *message)
{
    const struct timespec end = deadline();
    while (! *condition)
    {
        const int result = pthread_cond_timedwait(&pause_condition, &pause_mutex, &end);
        require(result == 0 || result == EINTR, message);
    }
}

line_task_submit_result_e __real_lineScheduleTask(line_t *, LineTaskFnNoBuf, tunnel_t *, LineTaskCancelFn);
line_task_submit_result_e __wrap_lineScheduleTask(line_t *, LineTaskFnNoBuf, tunnel_t *, LineTaskCancelFn);
line_task_submit_result_e __wrap_lineScheduleTask(line_t *line, LineTaskFnNoBuf task, tunnel_t *t,
                                                  LineTaskCancelFn cancel)
{
    require(line == normal_line && t == bridge && cancel == NULL, "unexpected scheduled control");
#if TEST_CONNECTION_TO_PACKETS
    require(task == ctpEstablishedTask, "CTP did not submit its Established notification");
#else
    require(task == ptcCloseLineTask, "PTC did not submit its peer-FIN reconciliation");
#endif
    require(currentThreadOwnsWorker(kOwner) && wwLwipEngineCurrent() != NULL,
            "required control did not originate inside its real owner engine");
    require(pthread_mutex_lock(&pause_mutex) == 0, "pause lock failed");
    paused = true;
    require(pthread_cond_broadcast(&pause_condition) == 0, "pause publication failed");
    waitFor(&released, "coordinator did not release the owner callback");
    require(pthread_mutex_unlock(&pause_mutex) == 0, "pause unlock failed");
    require(! atomicLoadExplicit(&getWorker(kOwner)->message_admission_open, memory_order_acquire),
            "real worker-message admission was still open at submission");
    const line_task_submit_result_e result = __real_lineScheduleTask(line, task, t, cancel);
    require(result == kLineTaskSubmitRejectedSettled, "real scheduler did not reject and settle control");
    ++submissions;
    return result;
}

void __real_bufferpoolReuseBuffer(buffer_pool_t *, sbuf_t *);
void __wrap_bufferpoolReuseBuffer(buffer_pool_t *, sbuf_t *);
void __wrap_bufferpoolReuseBuffer(buffer_pool_t *pool, sbuf_t *buffer)
{
    if (buffer == retained_buffer)
    {
        require(currentThreadOwnsWorker(kOwner) && pool == getWorkerBufferPool(kOwner),
                "retained bridge buffer settled outside its owner pool");
        require(++buffer_releases == 1, "retained bridge buffer settled twice");
    }
    __real_bufferpoolReuseBuffer(pool, buffer);
}

static uint32_t pcbUsed(void)
{
    require(wwLwipEngineCurrent() != NULL && lwip_stats.memp[MEMP_TCP_PCB] != NULL,
            "PCB statistics require the owner engine");
    return (uint32_t) lwip_stats.memp[MEMP_TCP_PCB]->used;
}

static void finished(tunnel_t *t, line_t *line)
{
    require(line == normal_line && currentThreadOwnsWorker(kOwner), "unexpected neighbor Finish");
#if TEST_CONNECTION_TO_PACKETS
    discard t;
    require(false, "CTP reflected source Finish while draining its borrowed line");
#else
    require(t == next, "PTC finished the wrong neighbor");
    ++neighbor_finishes;
#endif
}

void __real_nodemanagerStopWorkerResources(wid_t, const ww_lifecycle_context_t *);
void __wrap_nodemanagerStopWorkerResources(wid_t, const ww_lifecycle_context_t *);
void __wrap_nodemanagerStopWorkerResources(wid_t wid, const ww_lifecycle_context_t *context)
{
#if TEST_CONNECTION_TO_PACKETS
    ctpTunnelOnWorkerStop(bridge, wid, context);
#else
    ptcTunnelOnWorkerStop(bridge, wid, context);
#endif
    if (wid == kOwner)
    {
        require(atomicLoadExplicit(&callback_returned, memory_order_acquire), "drain raced the held callback");
#if TEST_CONNECTION_TO_PACKETS
        ctp_tstate_t *state = tunnelGetState(bridge);
        ctp_lstate_t *ls    = lineGetState(normal_line, bridge);
        require(state->terminal_lines[wid] == NULL && ctp_flow_map_t_size(&state->flows) == 0,
                "CTP owner drain retained terminal or flow registration");
        require(lineIsAlive(normal_line) && ls->tunnel == bridge && ls->tcp_pcb == NULL,
                "CTP owner drain did not preserve source-owned normal line state");
        require(bufferqueueGetBufLen(&ls->pending_queue) == 19, "CTP released source-owned pending lifetime early");
        tunnelNextUpStreamFinish(source, normal_line);
        require(lineIsAlive(normal_line), "CTP destroyed its borrowed normal line");
        require(neighbor_finishes == 0, "CTP reflected a Finish during source settlement");
        lineDestroy(normal_line);
        require(state->owned_lines[wid] == NULL, "source Finish retained CTP inventory");
#else
        ptc_tstate_t *state = tunnelGetState(bridge);
        require(state->owned_lines[wid] == NULL, "PTC owner drain retained its normal line");
        require(neighbor_finishes == 1, "PTC owner drain did not send exactly one Finish");
#endif
        require(! lineIsAlive(normal_line), "normal line remained logically alive after owner settlement");
        const uint8_t *bytes = lineGetState(normal_line, bridge);
        for (size_t i = 0; i < bridge->lstate_size; ++i)
            require(bytes[i] == 0, "owner settlement retained bridge line state");
        require(atomicLoadU32Relaxed(&normal_line->refc) == 1, "owner settlement leaked a line reference");
        require(buffer_releases == 1, "owner settlement did not release retained buffer once");
        lineUnref(normal_line);
        normal_line = NULL;
        ++owner_settlements;
    }
    require(lineIsAlive(tunnelchainGetWorkerPacketLine(chain, wid)), "owner drain destroyed a packet line");
    __real_nodemanagerStopWorkerResources(wid, context);
}

static void ownerCallback(void *worker, void *a, void *b, void *c)
{
    discard worker;
    discard a;
    discard b;
    discard c;
    require(currentThreadOwnsWorker(kOwner), "callback dispatched on wrong runtime worker");
    ww_lwip_engine_t *engine = wwLwipRuntimeGet(kOwner), *previous;
    require(engine != NULL && wwLwipEngineEnter(engine, &previous), "runtime owner engine unavailable");
    pcb_baseline        = pcbUsed();
    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
    require(pcb != NULL && pcbUsed() == pcb_baseline + 1, "PCB allocation did not charge once");
    pcb->state = ESTABLISHED;
    TCP_REG_ACTIVE(pcb);
    normal_line = lineCreate(tunnelchainGetLinePools(chain), kOwner);
    require(normal_line != NULL, "normal line creation failed");
    lineRef(normal_line); /* Fixture reference survives logical destruction. */
    retained_buffer = bufferpoolGetSmallBuffer(lineGetBufferPool(normal_line));
    sbufSetLength(retained_buffer, 19);
#if TEST_CONNECTION_TO_PACKETS
    ctp_lstate_t *ls = lineGetState(normal_line, bridge);
    ctpLinestateInitialize(ls, bridge, normal_line, kCtpLineKindTcp);
    ls->engine   = engine;
    ls->tcp_pcb  = pcb;
    ls->flow_key = (ctp_flow_key_t) {.local_port = 40001, .remote_port = 80, .protocol = IP_PROTO_TCP};
    require(ctpFlowRegister(bridge, ls, pcb, IP_PROTO_TCP), "CTP flow registration failed");
    require(bufferqueueTryPushBack(&ls->pending_queue, &retained_buffer), "CTP retained-buffer setup failed");
    tcp_arg(pcb, ls);
    tcp_recv(pcb, ctpTcpRecvCallback);
    tcp_sent(pcb, ctpTcpSentCallback);
    tcp_poll(pcb, ctpTcpPollCallback, kCtpWritePollInterval);
    tcp_err(pcb, ctpTcpErrorCallback);
    pcb->connected     = ctpTcpConnectedCallback;
    const err_t result = pcb->connected(pcb->callback_arg, pcb, ERR_OK);
    require(ls->tcp_pcb == NULL && ! ls->flow_registered && ls->terminal_pending,
            "CTP refusal did not detach its producer and publish terminal work");
    require(! ls->write_poll_armed && ! ls->write_retry_queued, "CTP refusal retained poll/retry work");
    ctp_tstate_t *state = tunnelGetState(bridge);
    require(state->terminal_lines[kOwner] == normal_line && ctp_flow_map_t_size(&state->flows) == 0,
            "CTP terminal registry or exact-flow detachment is incorrect");
#else
    ptc_lstate_t *ls = lineGetState(normal_line, bridge);
    ptcLinestateInitialize(ls, bridge, normal_line, kPtcLineKindTcp, pcb);
    ls->next_init_sent = true;
    ptcReserveWriteSlots(ls);
    ptcAckQueuePushBack(ls, retained_buffer, 19);
    ptcPauseQueuePushBack(ls, retained_buffer);
    retained_buffer = sbuf_ack_queue_t_front(&ls->ack_queue)->buf;
    tcp_arg(pcb, ls);
    tcp_recv(pcb, lwipThreadPtcTcpRecvCallback);
    tcp_sent(pcb, ptcTcpSendCompleteCallback);
    tcp_poll(pcb, ptcTcpPollCallback, kPtcWritePollInterval);
    ls->write_poll_armed = true;
    tcp_err(pcb, lwipThreadPtcTcpConnectionErrorCallback);
    const err_t result = pcb->recv(pcb->callback_arg, pcb, NULL, ERR_OK);
    require(ls->tcp_pcb == NULL && ls->terminal_required && ! ls->write_poll_armed && ! ls->write_retry_queued,
            "PTC refusal did not detach its producer and publish terminal work");
    ptc_tstate_t *state = tunnelGetState(bridge);
    require(state->owned_lines[kOwner] == normal_line, "PTC refusal lost its owner inventory");
#endif
    require(result == ERR_ABRT && pcbUsed() == pcb_baseline, "callback refusal did not release its PCB once");
    require(lineIsAlive(normal_line) && lineIsAlive(tunnelchainGetWorkerPacketLine(chain, kOwner)),
            "protocol callback destroyed a normal or packet line before owner drain");
    wwLwipEngineLeave(engine, previous);
    atomicStoreExplicit(&callback_returned, true, memory_order_release);
}

static void setupBridge(void)
{
    source = tunnelCreate(NULL, 0, 0);
    next   = tunnelCreate(NULL, 0, 0);
    require(source != NULL && next != NULL, "neighbor creation failed");
#if TEST_CONNECTION_TO_PACKETS
    bridge = tunnelCreate(NULL, sizeof(ctp_tstate_t), sizeof(ctp_lstate_t));
    require(bridge != NULL, "CTP fixture construction failed");
    bridge->fnFinU      = ctpTunnelUpStreamFinish;
    ctp_tstate_t *state = tunnelGetState(bridge);
    require(ctpFlowRegistryInitialize(state), "CTP registry initialization failed");
    state->netifs_count   = 2;
    state->netifs         = memoryAllocateZero(2 * sizeof(*state->netifs));
    state->owned_lines    = memoryAllocateZero(2 * sizeof(*state->owned_lines));
    state->terminal_lines = memoryAllocateZero(2 * sizeof(*state->terminal_lines));
    atomic_init(&state->stopping, false);
    atomic_init(&state->fragment_drops, 0);
    quiescenceGateInit(&state->prev_gate);
    quiescenceGateInit(&state->next_gate);
    quiescenceGateInit(&state->packet_ingress_gate);
    require(quiescenceGateOpen(&state->prev_gate) && quiescenceGateOpen(&state->next_gate) &&
                quiescenceGateOpen(&state->packet_ingress_gate),
            "CTP gate setup failed");
    source->fnFinD = finished;
#else
    static node_t node;
    bridge = ptcTunnelCreate(&node);
    require(bridge != NULL, "PTC fixture construction failed");
    ptcTunnelOnStart(bridge);
    next->fnFinU = finished;
#endif
    tunnelBind(source, bridge);
    tunnelBind(bridge, next);
    chain = tunnelchainCreate(2);
    require(chain != NULL, "chain creation failed");
    chain->sum_line_state_size  = bridge->lstate_size;
    chain->contains_packet_node = true;
    tunnelchainFinalize(chain);
    require(chain->finalized, "chain finalization failed");
    source->chain = bridge->chain = next->chain = chain;
}

static void runScenario(bool accepted_success)
{
    alarm(30);
    testCaseSet(accepted_success ? "accepted shutdown success then real bridge refusal"
                                 : "initial real bridge refusal");
    static char            off[]        = "OFF";
    ww_construction_data_t data         = {0};
    data.workers_count                  = 2;
    data.ram_profile                    = 4;
    data.mtu_size                       = 1500;
    data.internal_logger_data.log_level = off;
    data.core_logger_data.log_level     = off;
    data.network_logger_data.log_level  = off;
    data.dns_logger_data.log_level      = off;
    require(wwStartupSucceeded(createGlobalState(data)), "runtime startup failed");
    initTcpIpStack();
    setupBridge();
    require(applicationShutdownCommitRuntime(), "runtime commit failed");
    require(sendWorkerMessageForceQueueWithCleanup(kOwner, ownerCallback, NULL, NULL, NULL, NULL) ==
                kWorkerMessageSubmitAccepted,
            "owner callback admission failed");
    atomicStoreExplicit(&GSTATE.workers_run_flag, true, memory_order_release);
    require(pthread_mutex_lock(&pause_mutex) == 0, "coordinator pause lock failed");
    waitFor(&paused, "owner callback did not reach required submission");
    if (accepted_success)
    {
        require(requestProgramShutdown(0), "successful shutdown request was refused");
        require(applicationShutdownWasRequested() && applicationShutdownGetExitCode() == 0,
                "successful shutdown request was not accepted");
    }
    else
        require(! applicationShutdownWasRequested(), "shutdown was accepted before the initial refusal");
    require(workerRequestQuiesceWithContext(getWorker(kOwner), wwLifecycleProcessShutdown()),
            "production owner quiesce request was unavailable");
    require(! atomicLoadExplicit(&getWorker(kOwner)->message_admission_open, memory_order_acquire),
            "production quiesce did not close worker-message admission");
    released = true;
    require(pthread_cond_broadcast(&pause_condition) == 0, "owner callback release failed");
    require(pthread_mutex_unlock(&pause_mutex) == 0, "coordinator pause unlock failed");
    require(wloopRun(getWorkerLoop(0)) == kWLoopRunQuiesced, "coordinator loop did not quiesce");
    require(workerWaitForPhase(getWorker(kOwner), kWorkerLifecycleQuiesced, 10000), "owner callback did not quiesce");
    const int expected = accepted_success ? 0 : 1;
    require(applicationShutdownGetExitCode() == expected, "terminal refusal changed the selected shutdown status");
#if TEST_CONNECTION_TO_PACKETS
    ctpTunnelOnQuiesceRequest(bridge, wwLifecycleProcessShutdown());
    ctpTunnelOnQuiesceWait(bridge, wwLifecycleProcessShutdown());
#else
    ptcTunnelOnQuiesceRequest(bridge, wwLifecycleProcessShutdown());
    ptcTunnelOnQuiesceWait(bridge, wwLifecycleProcessShutdown());
#endif
    globalstateRunShutdownSequence();
    application_shutdown_snapshot_t final_status;
    require(applicationShutdownBeginFinalizing(&final_status) && final_status.exit_code == expected,
            "owner drain changed the final shutdown status");
    require(submissions == 1 && owner_settlements == 1 && buffer_releases == 1 && normal_line == NULL,
            "shutdown did not settle each bridge obligation exactly once");
    for (wid_t wid = 0; wid < 2; ++wid)
        require(lineIsAlive(tunnelchainGetWorkerPacketLine(chain, wid)), "shutdown destroyed a packet line");
#if TEST_CONNECTION_TO_PACKETS
    ctpTunnelOnStop(bridge, wwLifecycleProcessShutdown());
#else
    ptcTunnelOnStop(bridge, wwLifecycleProcessShutdown());
#endif
    tunnelchainDestroy(chain);
#if TEST_CONNECTION_TO_PACKETS
    ctpTunnelDestroy(bridge, wwLifecycleProcessShutdown());
#else
    ptcTunnelDestroy(bridge, wwLifecycleProcessShutdown());
#endif
    tunnelDestroy(source);
    tunnelDestroy(next);
    destroyGlobalState();
    alarm(0);
}

int main(void)
{
    for (unsigned scenario = 0; scenario < 2; ++scenario)
    {
        const pid_t child = fork();
        require(child >= 0, "scenario fork failed");
        if (child == 0)
        {
            runScenario(scenario == 0);
            _Exit(0);
        }
        int status;
        require(waitpid(child, &status, 0) == child, "scenario wait failed");
        require(WIFEXITED(status) && WEXITSTATUS(status) == 0, "shutdown refusal scenario failed");
    }
    puts("real bridge shutdown refusal status and owner settlement passed");
    return 0;
}
