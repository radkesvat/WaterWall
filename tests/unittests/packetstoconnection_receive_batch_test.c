/* PTC receive staging stays owned by the line until deferred delivery. */
#include "PacketsToConnection/structure.h"
#include "lwip_test_runtime.h"
#include "tunnel_line_failure_harness.h"

typedef struct fixture_s
{
    twf_worker_env_t          env;
    tunnel_t                 *ptc;
    tunnel_t                 *next;
    tunnel_chain_t           *chain;
    line_t                   *line;
    ww_lwip_engine_t         *engine;
    interface_route_context_t route;
    uint32_t                  submitted;
    uint32_t                  delivered;
    unsigned                  payloads;
    unsigned                  finishes;
    bool                      inject_on_init;
    bool                      close_on_init;
    bool                      close_on_payload;
    bool                      pause_on_payload;
} fixture_t;

typedef struct queued_task_s
{
    line_t           *line;
    tunnel_t         *tunnel;
    LineTaskFnNoBuf   callback;
    LineTaskFnWithBuf buffered_callback;
    sbuf_t           *buffer;
} queued_task_t;

static fixture_t    *fixture;
static queued_task_t tasks[1024];
static unsigned      task_count;
static bool          reject_task;

line_task_submit_result_e __wrap_lineScheduleTask(line_t *line, LineTaskFnNoBuf callback, tunnel_t *tunnel,
                                                  LineTaskCancelFn on_cancel);
line_task_submit_result_e __wrap_lineScheduleTaskWithBuf(line_t *line, LineTaskFnWithBuf callback, tunnel_t *tunnel,
                                                         sbuf_t *buffer, LineTaskCancelFn on_cancel);
line_task_submit_result_e __wrap_lineScheduleTask(line_t *line, LineTaskFnNoBuf callback, tunnel_t *tunnel,
                                                  LineTaskCancelFn on_cancel)
{
    twfRequire(on_cancel == NULL, "receive scheduling installed an owner-unsafe cancellation callback");
    if (reject_task)
        return kLineTaskSubmitRejectedSettled;
    twfRequire(task_count < ARRAY_SIZE(tasks), "receive task queue overflow");
    lineRef(line);
    tasks[task_count++] = (queued_task_t) {.line = line, .tunnel = tunnel, .callback = callback};
    return kLineTaskSubmitAcceptedAsync;
}

/* Also model the original per-pbuf scheduling path, so the before-fix fixture
 * fails on the batching assertion rather than requiring a running scheduler. */
line_task_submit_result_e __wrap_lineScheduleTaskWithBuf(line_t *line, LineTaskFnWithBuf callback, tunnel_t *tunnel,
                                                         sbuf_t *buffer, LineTaskCancelFn on_cancel)
{
    twfRequire(on_cancel == NULL, "unexpected buffered cancellation callback");
    if (reject_task)
    {
        lineReuseBuffer(line, buffer);
        return kLineTaskSubmitRejectedSettled;
    }
    twfRequire(task_count < ARRAY_SIZE(tasks), "buffered receive task queue overflow");
    lineRef(line);
    tasks[task_count++] =
        (queued_task_t) {.line = line, .tunnel = tunnel, .buffered_callback = callback, .buffer = buffer};
    return kLineTaskSubmitAcceptedAsync;
}

static void runTask(void)
{
    twfRequire(task_count != 0, "no deferred task to run");
    twfRequire(wwLwipEngineCurrent() == NULL, "receive delivery reentered the active stack");
    const queued_task_t task = tasks[0];
    memmove(tasks, tasks + 1, --task_count * sizeof(tasks[0]));
    if (lineIsAlive(task.line))
    {
        if (task.buffer != NULL)
            task.buffered_callback(task.tunnel, task.line, task.buffer);
        else
            task.callback(task.tunnel, task.line);
    }
    else if (task.buffer != NULL)
        lineReuseBuffer(task.line, task.buffer);
    lineUnref(task.line);
}

static struct pbuf *makeInput(uint16_t length)
{
    struct pbuf *p = pbuf_alloc(PBUF_RAW, length, PBUF_RAM);
    twfRequire(p != NULL, "receive test pbuf allocation failed");
    twfRequire(p->len == length, "receive fixture expected one contiguous pbuf");
    for (uint32_t i = 0; i < length; ++i)
        ((uint8_t *) p->payload)[i] = (uint8_t) (fixture->submitted + i);
    return p;
}

static void submit(uint16_t length)
{
    ptc_lstate_t     *ls = lineGetState(fixture->line, fixture->ptc);
    ww_lwip_engine_t *previous;
    twfRequire(wwLwipEngineEnter(fixture->engine, &previous), "receive fixture cannot enter engine");
    struct pbuf *p = makeInput(length);
    twfRequire(lwipThreadPtcTcpRecvCallback(ls, ls->tcp_pcb, p, ERR_OK) == ERR_OK, "receive callback refused data");
    fixture->submitted += length;
    wwLwipEngineLeave(fixture->engine, previous);
}

static void onInit(tunnel_t *t, line_t *l)
{
    discard t;
    if (fixture->inject_on_init)
    {
        fixture->inject_on_init = false;
        submit(31);
    }
    if (fixture->close_on_init)
        ptcTunnelDownStreamFinish(fixture->ptc, l);
}

static void onPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard        t;
    const uint32_t length = sbufGetLength(buf);
    const uint8_t *bytes  = sbufGetRawPtr(buf);
    for (uint32_t i = 0; i < length; ++i)
        twfRequire(bytes[i] == (uint8_t) (fixture->delivered + i), "coalescing changed receive bytes or FIFO order");
    fixture->delivered += length;
    ++fixture->payloads;
    lineReuseBuffer(l, buf);
    if (fixture->pause_on_payload)
        ptcTunnelDownStreamPause(fixture->ptc, l);
    if (fixture->close_on_payload)
        ptcTunnelDownStreamFinish(fixture->ptc, l);
}

static void onFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    twfRequire(fixture->delivered == fixture->submitted, "FIN overtook deferred receive bytes");
    ++fixture->finishes;
}

static void setup(fixture_t *f)
{
    memoryZero(f, sizeof(*f));
    fixture     = f;
    task_count  = 0;
    reject_task = false;
    twfWorkerEnvSetupWithBufferSizes(&f->env, 131072, 4096, 32, 131072, 131072);
    f->engine = wwLwipEngineCreate(0, f->env.loop);
    twfRequire(f->engine != NULL, "receive fixture engine allocation failed");
    f->ptc  = tunnelCreate(NULL, sizeof(ptc_tstate_t), sizeof(ptc_lstate_t));
    f->next = tunnelCreate(NULL, 0, 0);
    twfRequire(f->ptc != NULL && f->next != NULL, "receive fixture tunnel allocation failed");
    f->next->fnInitU    = onInit;
    f->next->fnPayloadU = onPayload;
    f->next->fnFinU     = onFinish;
    tunnelBind(f->ptc, f->next);
    f->chain = tunnelchainCreate(1);
    twfRequire(f->chain != NULL, "receive fixture chain allocation failed");
    f->chain->sum_line_state_size  = f->ptc->lstate_size;
    f->chain->contains_packet_node = true;
    tunnelchainFinalize(f->chain);
    twfRequire(f->chain->finalized, "receive fixture chain finalization failed");
    f->ptc->chain          = f->chain;
    ptc_tstate_t *ts       = tunnelGetState(f->ptc);
    ts->mtu                = 1500;
    ts->owned_worker_count = 1;
    ts->owned_lines        = memoryAllocateZero(sizeof(*ts->owned_lines));
    twfRequire(ts->owned_lines != NULL, "receive fixture owner registry allocation failed");
    mutexInit(&ts->owned_lines_lock);
    mutexInit(&ts->drain_lock);
    atomic_init(&ts->stopping, false);
    quiescenceGateInit(&ts->output_gate);
    quiescenceGateInit(&ts->next_gate);
    twfRequire(quiescenceGateOpen(&ts->output_gate) && quiescenceGateOpen(&ts->next_gate), "receive gates failed");
    f->line = lineCreate(tunnelchainGetLinePools(f->chain), 0);
    ww_lwip_engine_t *previous;
    twfRequire(wwLwipEngineEnter(f->engine, &previous), "receive fixture engine entry failed");
    struct tcp_pcb *pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
    twfRequire(pcb != NULL, "receive fixture PCB allocation failed");
    ptc_lstate_t *ls = lineGetState(f->line, f->ptc);
    twfRequire(ptcLinestateInitialize(ls, f->ptc, f->line, kPtcLineKindTcp, pcb), "receive state init failed");
    f->route.engine = f->engine;
    f->route.tunnel = f->ptc;
    ls->route_ctx   = &f->route;
    tcp_arg(pcb, ls);
    tcp_recv(pcb, lwipThreadPtcTcpRecvCallback);
    tcp_err(pcb, lwipThreadPtcTcpConnectionErrorCallback);
    wwLwipEngineLeave(f->engine, previous);
}

static void teardown(fixture_t *f)
{
    if (f->line != NULL)
    {
        /* These teardown cases may intentionally cancel accepted receive data. */
        f->submitted = f->delivered;
        ptcCloseLineForStop(f->ptc, f->line);
        f->line = NULL;
    }
    while (task_count != 0)
        runTask();
    twfRequireNoLeakedBuffers();
    ptc_tstate_t *ts = tunnelGetState(f->ptc);
    twfRequire(ts->owned_lines[0] == NULL, "receive teardown left an owned line");
    twfRequire(f->route.drains == NULL && ts->drain_count == 0, "receive teardown retained its closing PCB");
    mutexDestroy(&ts->owned_lines_lock);
    mutexDestroy(&ts->drain_lock);
    memoryFree(ts->owned_lines);
    twfRequire(lineIsAlive(tunnelchainGetWorkerPacketLine(f->chain, 0)), "receive path destroyed its packet line");
    tunnelchainDestroy(f->chain);
    tunnelDestroy(f->next);
    tunnelDestroy(f->ptc);
    wwLwipEngineDestroy(f->engine);
    twfWorkerEnvTeardown(&f->env);
    fixture = NULL;
}

static void caseBatchAndPause(void)
{
    twfSetCase("PTC batches beyond uint16 length and returns aggregated paused credit");
    fixture_t f;
    setup(&f);
    for (unsigned i = 0; i < 90; ++i)
        submit(1460);
    twfRequireEqualU32(task_count, 1, "PTC scheduled one task per segment");
    twfRequire(f.payloads == 0, "PTC delivered from active lwIP input");
    ptcTunnelDownStreamPause(f.ptc, f.line);
    f.pause_on_payload = true;
    runTask();
    ptc_lstate_t *ls = lineGetState(f.line, f.ptc);
    twfRequireEqualU32(f.payloads, 1, "PTC did not publish one coalesced Payload");
    twfRequireEqualU32(ls->read_paused_len, f.submitted, "PTC lost aggregated paused credit");
    twfRequireEqualU32(ls->rx_uncredited, f.submitted, "PTC returned paused credit early");
    ptcTunnelDownStreamResume(f.ptc, f.line);
    twfRequire(ls->rx_uncredited == 0 && ls->read_paused_len == 0, "PTC failed to return credit beyond uint16");
    teardown(&f);
}

static void caseReentryAndFin(void)
{
    twfSetCase("PTC detaches before reentrant Init and preserves receive-before-FIN FIFO");
    fixture_t f;
    setup(&f);
    f.inject_on_init = true;
    submit(1460);
    runTask();
    twfRequireEqualU32(task_count, 1, "reentrant receive did not own a separate deferred task");
    ptc_lstate_t     *ls = lineGetState(f.line, f.ptc);
    ww_lwip_engine_t *previous;
    twfRequire(wwLwipEngineEnter(f.engine, &previous), "FIN fixture engine entry failed");
    twfRequire(lwipThreadPtcTcpRecvCallback(ls, ls->tcp_pcb, NULL, ERR_OK) == ERR_OK, "FIN callback failed");
    wwLwipEngineLeave(f.engine, previous);
    twfRequireEqualU32(task_count, 2, "FIN did not follow queued receive data");
    runTask();
    twfRequire(f.delivered == f.submitted && f.finishes == 0, "FIN or receive order changed");
    line_t *line = f.line;
    lineRef(line);
    runTask();
    twfRequire(! lineIsAlive(line) && f.finishes == 1, "PTC FIN failed to retire owner line");
    lineUnref(line);
    f.line = NULL;
    teardown(&f);
}

static void caseCloseDuringDelivery(bool during_init)
{
    twfSetCase("PTC settles a detached receive when next closes reentrantly");
    fixture_t f;
    setup(&f);
    f.close_on_init    = during_init;
    f.close_on_payload = ! during_init;
    submit(1460);
    line_t *line = f.line;
    lineRef(line);
    runTask();
    twfRequire(! lineIsAlive(line), "reentrant next Finish left PTC owner alive");
    twfRequireLineStateZeroed(line, f.ptc, "reentrant close retained PTC receive state");
    lineUnref(line);
    f.line = NULL;
    twfRequireEqualU32(f.payloads, during_init ? 0 : 1, "receive callback ran after Init closed the line");
    teardown(&f);
}

static void caseBoundAndCancellation(void)
{
    twfSetCase("PTC caps pending receive and owner drain settles canceled tasks");
    fixture_t f;
    setup(&f);
    for (unsigned i = 0; i < TCP_WND / 8192; ++i)
        submit(8192);
    ptc_lstate_t *ls = lineGetState(f.line, f.ptc);
    twfRequireEqualU32(sbufGetLength(ls->rx_delivery), TCP_WND, "receive did not reach its exact bound");
    twfRequire(sbufGetMaximumWriteableSize(ls->rx_delivery) <= TCP_WND, "receive staging exceeded its storage bound");
    ww_lwip_engine_t *previous;
    twfRequire(wwLwipEngineEnter(f.engine, &previous), "bound fixture engine entry failed");
    struct pbuf *p = makeInput(1);
    twfRequire(lwipThreadPtcTcpRecvCallback(ls, ls->tcp_pcb, p, ERR_OK) == ERR_MEM, "receive exceeded TCP_WND bound");
    twfRequireEqualU32(p->ref, 1, "bound refusal consumed lwIP's replay pbuf");
    pbuf_free(p);
    wwLwipEngineLeave(f.engine, previous);
    twfRequire(task_count == 1 && ls->rx_uncredited == TCP_WND, "bound refusal changed task/credit ownership");
    /* Cancel the scheduler's reference before owner Stop, without entering line
     * state or touching the owner's staging storage from cancellation. */
    const queued_task_t canceled = tasks[--task_count];
    testWorkerBindWID(kInvalidWID);
    lineUnref(canceled.line);
    testWorkerBindWID(0);
    twfRequireEqualU32(sbufGetLength(ls->rx_delivery), TCP_WND, "cancellation stole owner receive storage");
    teardown(&f);
}

static void caseRefusalThenRetry(void)
{
    twfSetCase("PTC submission refusal preserves a chained pbuf for exact retry");
    fixture_t f;
    setup(&f);
    ptc_lstate_t     *ls = lineGetState(f.line, f.ptc);
    ww_lwip_engine_t *previous;
    twfRequire(wwLwipEngineEnter(f.engine, &previous), "refusal fixture engine entry failed");
    struct pbuf *first = makeInput(1000);
    f.submitted        = 1000;
    struct pbuf *last  = makeInput(1000);
    f.submitted        = 0;
    pbuf_cat(first, last);
    reject_task = true;
    twfRequire(lwipThreadPtcTcpRecvCallback(ls, ls->tcp_pcb, first, ERR_OK) == ERR_MEM,
               "refused scheduling did not request pbuf replay");
    twfRequire(first->ref == 1 && first->next == last && last->ref == 1, "refusal consumed the original pbuf chain");
    twfRequire(ls->rx_delivery == NULL && ls->rx_uncredited == 0 && task_count == 0,
               "refusal retained staged buffer, receive credit, or task");
    twfRequireNoLeakedBuffers();
    reject_task = false;
    twfRequire(lwipThreadPtcTcpRecvCallback(ls, ls->tcp_pcb, first, ERR_OK) == ERR_OK, "receive replay failed");
    f.submitted = 2000;
    wwLwipEngineLeave(f.engine, previous);
    runTask();
    twfRequire(f.delivered == 2000 && f.payloads == 1 && ls->rx_uncredited == 0,
               "receive replay changed bytes or credit");
    teardown(&f);
}

int main(void)
{
    twfRequire(lwipTestRuntimeInitialize(), "failed to initialize lwIP receive runtime");
    wwLwipEngineSharedInit();
    ptcRxWrapperPoolInitializeOnce();
    caseBatchAndPause();
    caseReentryAndFin();
    caseCloseDuringDelivery(true);
    caseCloseDuringDelivery(false);
    caseBoundAndCancellation();
    caseRefusalThenRetry();
    wwLwipEngineSharedCleanup();
    lwipTestRuntimeCleanup();
    puts("packetstoconnection_receive_batch_test: all cases passed");
    return 0;
}
