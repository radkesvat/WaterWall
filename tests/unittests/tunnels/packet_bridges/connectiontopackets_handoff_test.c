/* CTest: waterwall.connectiontopackets_handoff_unit.
 * Bounded in-memory dispatch fixture: byte/entry refusal, delivery, cancellation,
 * stale flow/shutdown, and custom-pbuf retention through tunnel destruction. */
#include "ConnectionToPackets/structure.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "fixtures/lwip/lwip_test_runtime.h"
#include <pthread.h>

typedef struct queued_s
{
    WorkerMessageCallback        callback;
    WorkerMessageCleanupCallback cleanup;
    void                        *args[3];
} queued_t;

static queued_t     queued[8];
static unsigned     queued_count;
static bool         refuse_queue, flow_alive;
static struct pbuf *retained_pbuf;
static unsigned     output_deliveries;
static void        *observed_budget;
static unsigned     budget_frees;

void __real_memoryFree(void *ptr);
void __wrap_memoryFree(void *ptr);
void __wrap_memoryFree(void *ptr)
{
    if (ptr == observed_budget && ptr != NULL)
        ++budget_frees;
    __real_memoryFree(ptr);
}

static worker_message_submit_result_e queueRetain(wid_t wid, WorkerMessageCallback callback,
                                                  WorkerMessageCleanupCallback cleanup, void *a, void *b, void *c)
{
    twfRequire(wid == 0, "handoff changed the selected worker");
    if (refuse_queue)
        return kWorkerMessageSubmitRejectedCallerRetains;
    twfRequire(queued_count < ARRAY_SIZE(queued), "fixture queue overflow");
    queued[queued_count++] = (queued_t) {.callback = callback, .cleanup = cleanup, .args = {a, b, c}};
    return kWorkerMessageSubmitAccepted;
}

static worker_message_submit_result_e queueCleanup(wid_t wid, WorkerMessageCallback callback,
                                                   WorkerMessageCleanupCallback cleanup, void *a, void *b, void *c)
{
    if (queueRetain(wid, callback, cleanup, a, b, c) == kWorkerMessageSubmitAccepted)
        return kWorkerMessageSubmitAccepted;
    cleanup(a, b, c, kWorkerMessageCancelEnqueueFailure);
    return kWorkerMessageSubmitRejectedCleanupRan;
}

static bool flowStillOwns(tunnel_t *t, const ctp_flow_key_t *key, uint64_t generation, wid_t wid)
{
    discard t;
    discard key;
    twfRequire(generation == 1 && wid == 0, "handoff changed its flow generation/owner");
    return flow_alive;
}

static void drainTerminal(tunnel_t *t, wid_t wid)
{
    discard t;
    discard wid;
}

static int retainInput(ww_lwip_engine_t *engine, struct pbuf *p, struct netif *netif)
{
    discard engine;
    discard netif;
    twfRequire(retained_pbuf == NULL, "input replaced a retained pbuf");
    retained_pbuf = p;
    return ERR_OK;
}

#define sendWorkerMessageForceQueueRetainOnRefusal queueRetain
#define sendWorkerMessageForceQueueWithCleanup     queueCleanup
#define ctpFlowStillOwns                           flowStillOwns
#define ctpDrainTerminalLinesOnCurrentWorker       drainTerminal
#define wwLwipEngineInput                          retainInput
#include "common/netif.c"
#include "downstream/payload.c"
#undef wwLwipEngineInput
#undef ctpDrainTerminalLinesOnCurrentWorker
#undef ctpFlowStillOwns
#undef sendWorkerMessageForceQueueWithCleanup
#undef sendWorkerMessageForceQueueRetainOnRefusal

static void settle(worker_t *worker, bool cancel)
{
    twfRequire(queued_count != 0, "no handoff queued");
    queued_t item = queued[0];
    memmove(queued, queued + 1, --queued_count * sizeof(queued[0]));
    if (cancel)
    {
        testWorkerBindWID(kInvalidWID);
        item.cleanup(item.args[0], item.args[1], item.args[2], kWorkerMessageCancelTeardown);
        testWorkerBindWID(0);
    }
    else
        item.callback(worker, item.args[0], item.args[1], item.args[2]);
}

static void packetOutput(tunnel_t *t, line_t *line, sbuf_t *buf)
{
    discard t;
    twfRequire(sbufGetLength(buf) == 64, "packet output changed length");
    ++output_deliveries;
    lineReuseBuffer(line, buf);
}

static void requireEmpty(ctp_handoff_budget_t *budget)
{
    twfRequire(budget->bytes == 0 && budget->entries == 0, "handoff reservation leaked");
}

typedef struct reservation_thread_s
{
    ctp_handoff_budget_t *budget;
    pthread_barrier_t    *barrier;
    bool                  admitted;
} reservation_thread_t;

static void *reserveConcurrently(void *arg)
{
    reservation_thread_t *thread = arg;
    thread->admitted             = ctpHandoffReserve(thread->budget, 64, true);
    int result                   = pthread_barrier_wait(thread->barrier);
    twfRequire(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD, "reservation barrier failed");
    result = pthread_barrier_wait(thread->barrier);
    twfRequire(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD, "release barrier failed");
    if (thread->admitted)
        ctpHandoffRelease(thread->budget, 64);
    return NULL;
}

static void caseConcurrentQuota(void)
{
    ctp_handoff_budget_t *budget = ctpHandoffBudgetCreate(64, 1);
    twfRequire(budget != NULL, "concurrent budget creation failed");
    pthread_barrier_t barrier;
    twfRequire(pthread_barrier_init(&barrier, NULL, 3) == 0, "quota barrier creation failed");
    reservation_thread_t args[2] = {{.budget = budget, .barrier = &barrier}, {.budget = budget, .barrier = &barrier}};
    pthread_t            threads[2];
    for (unsigned i = 0; i < 2; ++i)
        twfRequire(pthread_create(&threads[i], NULL, reserveConcurrently, &args[i]) == 0, "quota thread creation");
    int result = pthread_barrier_wait(&barrier);
    twfRequire(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD, "quota admission barrier");
    twfRequire(args[0].admitted != args[1].admitted && budget->bytes == 64 && budget->entries == 1,
               "concurrent producers over-admitted the shared quota");
    result = pthread_barrier_wait(&barrier);
    twfRequire(result == 0 || result == PTHREAD_BARRIER_SERIAL_THREAD, "quota settlement barrier");
    for (unsigned i = 0; i < 2; ++i)
        twfRequire(pthread_join(threads[i], NULL) == 0, "quota thread join");
    twfRequire(pthread_barrier_destroy(&barrier) == 0, "quota barrier destruction");
    requireEmpty(budget);
    ctpHandoffBudgetDetach(budget);
}

int main(void)
{
    twfSetCase("CTP shared handoff admission and all terminal ownership paths");
    twfRequire(lwipTestRuntimeInitialize(), "lwIP fixture initialization failed");
    caseConcurrentQuota();
    wwLwipEngineSharedInit();
    twf_worker_env_t env;
    twfWorkerEnvSetupWithSmallBuffers(&env, 4096, 1024, 0);
    ww_lwip_engine_t *engine = wwLwipEngineCreate(0, env.loop);
    twfRequire(engine != NULL, "handoff engine creation failed");
    tunnel_t *t    = tunnelCreate(NULL, sizeof(ctp_tstate_t), 0);
    tunnel_t *next = tunnelCreate(NULL, 0, 0);
    twfRequire(t != NULL && next != NULL, "handoff tunnel creation failed");
    tunnelBind(t, next);
    next->fnPayloadU            = packetOutput;
    tunnel_chain_t *chain       = tunnelchainCreate(1);
    chain->contains_packet_node = true;
    tunnelchainFinalize(chain);
    t->chain            = chain;
    ctp_tstate_t *state = tunnelGetState(t);
    atomic_init(&state->stopping, false);
    quiescenceGateInit(&state->next_gate);
    twfRequire(quiescenceGateOpen(&state->next_gate), "next gate did not open");
    ctp_netif_ctx_t ctx       = {.tunnel = t, .wid = 0, .engine = engine, .added = true};
    ctx.netif.state           = &ctx;
    ctp_netif_ctx_t *netifs[] = {&ctx};
    state->netifs             = netifs;
    state->netifs_count       = 1;

    const size_t emit_charge = sizeof(ctp_packet_emit_msg_t) + 64U;
    state->handoff_budget    = ctpHandoffBudgetCreate(emit_charge, 4);
    twfRequire(state->handoff_budget != NULL, "handoff budget creation failed");
    uint8_t bytes[64] = {0x45};
    bytes[9]          = IP_PROTO_UDP;
    PUT_BE16(bytes + 2, sizeof(bytes));
    struct pbuf       p = {.payload = bytes, .len = sizeof(bytes), .tot_len = sizeof(bytes), .ref = 1};
    ww_lwip_engine_t *previous;
    twfRequire(wwLwipEngineEnter(engine, &previous), "output engine entry");
    twfRequire(ctpNetifOutput(&ctx.netif, &p, NULL) == ERR_OK && queued_count == 1 && output_deliveries == 0,
               "output did not force queue");
    twfRequire(ctpNetifOutput(&ctx.netif, &p, NULL) == ERR_MEM && queued_count == 1 &&
                   state->handoff_budget->bytes == emit_charge && state->handoff_budget->egress_refused == 1,
               "output exceeded byte budget");
    wwLwipEngineLeave(engine, previous);
    settle(&env.worker, false);
    twfRequire(output_deliveries == 1, "accepted output did not deliver");
    requireEmpty(state->handoff_budget);
    for (unsigned mode = 0; mode < 3; ++mode)
    {
        refuse_queue = mode == 0;
        twfRequire(wwLwipEngineEnter(engine, &previous), "output retry engine entry");
        twfRequire(ctpNetifOutput(&ctx.netif, &p, NULL) == (refuse_queue ? ERR_MEM : ERR_OK), "output retry result");
        wwLwipEngineLeave(engine, previous);
        if (mode == 1)
            settle(&env.worker, true);
        if (mode == 2)
        {
            atomicStoreRelaxed(&state->stopping, true);
            settle(&env.worker, false);
            atomicStoreRelaxed(&state->stopping, false);
        }
        requireEmpty(state->handoff_budget);
    }
    refuse_queue = false;
    ctpHandoffBudgetDetach(state->handoff_budget);

    /* A tiny count quota catches small allocations independently of byte use. */
    state->handoff_budget    = ctpHandoffBudgetCreate(4096, 2);
    ctp_inject_msg_t *first  = ctpAllocatePacketMessage(state->handoff_budget, 48);
    ctp_inject_msg_t *second = ctpAllocatePacketMessage(state->handoff_budget, 48);
    twfRequire(first != NULL && second != NULL && ctpAllocatePacketMessage(state->handoff_budget, 48) == NULL &&
                   state->handoff_budget->entries == 2 && state->handoff_budget->ingress_refused == 1,
               "input exceeded entry budget");
    ctpInjectMessageDestroy(first);
    ctpInjectMessageDestroy(second);
    requireEmpty(state->handoff_budget);

    ctp_flow_key_t key = {.protocol = IP_PROTO_TCP};
    for (unsigned mode = 0; mode < 4; ++mode)
    {
        ctp_inject_msg_t *msg = ctpAllocatePacketMessage(state->handoff_budget, 48);
        twfRequire(msg != NULL, "input admission did not recover");
        refuse_queue = mode == 0;
        twfRequire(ctpInjectPublish(t, &key, 1, 0, NULL, 0, msg).accepted == ! refuse_queue,
                   "input publication result");
        if (mode == 1)
            settle(&env.worker, true);
        if (mode == 2 || mode == 3)
        {
            flow_alive = mode == 3;
            atomicStoreRelaxed(&state->stopping, mode == 3);
            settle(&env.worker, false);
            atomicStoreRelaxed(&state->stopping, false);
        }
        requireEmpty(state->handoff_budget);
    }

    refuse_queue             = false;
    flow_alive               = true;
    ctp_inject_msg_t *msg    = ctpAllocatePacketMessage(state->handoff_budget, 48);
    const size_t      charge = msg->charge;
    twfRequire(ctpInjectPublish(t, &key, 1, 0, NULL, 0, msg).accepted, "retained input publication");
    settle(&env.worker, false);
    twfRequire(retained_pbuf != NULL && state->handoff_budget->bytes == charge && state->handoff_budget->entries == 1,
               "custom pbuf charge was released at dispatch instead of actual free");
    ctp_handoff_budget_t *budget = state->handoff_budget;
    observed_budget              = budget;
    budget_frees                 = 0;
    ctpHandoffBudgetDetach(budget);
    state->handoff_budget = NULL;
    tunnelDestroy(t);
    twfRequire(budget->detached && budget->entries == 1, "live pbuf lost its independent budget lifetime");
    twfRequire(wwLwipEngineEnter(engine, &previous), "pbuf release engine entry");
    pbuf_free(retained_pbuf);
    retained_pbuf = NULL;
    wwLwipEngineLeave(engine, previous);
    twfRequire(budget_frees == 1, "last custom pbuf did not release its budget object exactly once");
    observed_budget = NULL;

    twfRequire(queued_count == 0 && lineIsAlive(tunnelchainGetWorkerPacketLine(chain, 0)),
               "handoff leaked tasks or destroyed a packet line");
    twfRequireNoLeakedBuffers();
    tunnelchainDestroy(chain);
    tunnelDestroy(next);
    wwLwipEngineDestroy(engine);
    twfWorkerEnvTeardown(&env);
    wwLwipEngineSharedCleanup();
    lwipTestRuntimeCleanup();
    puts("connectiontopackets_handoff_test: all cases passed");
    return 0;
}
