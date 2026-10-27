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
static sbuf_t      *expected_output_buffer;
static uint8_t      expected_output_bytes[9000];
static uint32_t     expected_output_length = 64;
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

static sbuf_t *createOutputBuffer(uint32_t length, uint16_t padding)
{
    return twfTrackAcquired(sbufCreateWithPadding(length, padding));
}

#define sendWorkerMessageForceQueueRetainOnRefusal queueRetain
#define sendWorkerMessageForceQueueWithCleanup     queueCleanup
#define ctpFlowStillOwns                           flowStillOwns
#define ctpDrainTerminalLinesOnCurrentWorker       drainTerminal
#define wwLwipEngineInput                          retainInput
#define sbufCreateWithPadding                      createOutputBuffer
#include "common/netif.c"
#undef sbufCreateWithPadding
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
    twfRequire(sbufGetLength(buf) == expected_output_length, "packet output changed length");
    twfRequire(buf == expected_output_buffer, "queued packet storage was replaced at delivery");
    twfRequire(sbufGetLeftPadding(buf) >= 64 && sbufGetLeftCapacity(buf) >= 64,
               "queued packet lost the onward chain's padding");
    twfRequire(memcmp(sbufGetRawPtr(buf), expected_output_bytes, expected_output_length) == 0,
               "queued packet did not preserve its detached bytes");
    expected_output_buffer = NULL;
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
    twfWorkerEnvSetupWithSmallBuffers(&env, 4096, 1024, 64);
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

    const size_t emit_charge = kCpuLineCacheSize + 64U + sizeof(sbuf_t) + kSbufAllocationAlignment;
    state->handoff_budget    = ctpHandoffBudgetCreate(emit_charge, 4);
    twfRequire(state->handoff_budget != NULL, "handoff budget creation failed");
    uint8_t bytes[64] = {0x45};
    bytes[9]          = IP_PROTO_UDP;
    PUT_BE16(bytes + 2, sizeof(bytes));
    for (unsigned i = 28; i < sizeof(bytes); ++i)
        bytes[i] = (uint8_t) i;
    memoryCopy(expected_output_bytes, bytes, sizeof(bytes));
    uint8_t           queued_packet_bytes[16] = {0xA5};
    struct pbuf       next_packet             = {.payload = queued_packet_bytes, .len = 16, .tot_len = 16, .ref = 1};
    struct pbuf       tail  = {.next = &next_packet, .payload = bytes + 23, .len = 41, .tot_len = 41, .ref = 1};
    struct pbuf       empty = {.next = &tail, .len = 0, .tot_len = 41, .ref = 1};
    struct pbuf       p     = {.next = &empty, .payload = bytes, .len = 23, .tot_len = sizeof(bytes), .ref = 1};
    ww_lwip_engine_t *previous;
    twfRequire(wwLwipEngineEnter(engine, &previous), "output engine entry");
    twfRequire(ctpNetifOutput(&ctx.netif, &p, NULL) == ERR_OK && queued_count == 1 && output_deliveries == 0,
               "output did not force queue");
    expected_output_buffer = queued[0].args[1];
    twfRequire(sbufGetAllocationCharge(expected_output_buffer) == emit_charge,
               "output budget did not charge the complete buffer allocation");
    twfRequire(ctpNetifOutput(&ctx.netif, &p, NULL) == ERR_MEM && queued_count == 1 &&
                   state->handoff_budget->bytes == emit_charge && state->handoff_budget->egress_refused == 1,
               "output exceeded byte budget");
    wwLwipEngineLeave(engine, previous);
    memorySet(bytes, 0xA5, sizeof(bytes));
    settle(&env.worker, false);
    memoryCopy(bytes, expected_output_bytes, sizeof(bytes));
    twfRequire(output_deliveries == 1, "accepted output did not deliver");
    requireEmpty(state->handoff_budget);
    for (unsigned mode = 0; mode < 4; ++mode)
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
        if (mode == 3)
        {
            quiescenceGateClose(&state->next_gate);
            settle(&env.worker, false);
            twfRequire(quiescenceGateOpen(&state->next_gate), "next gate did not reopen");
        }
        requireEmpty(state->handoff_budget);
    }
    refuse_queue = false;
    ctpHandoffBudgetDetach(state->handoff_budget);

    /* Detached buffers stay close to packet size, independently of pool tiers. */
    state->handoff_budget  = ctpHandoffBudgetCreate(10000, 2);
    const uint16_t sizes[] = {40, 1500, 9000};
    for (unsigned i = 0; i < ARRAY_SIZE(sizes); ++i)
    {
        expected_output_length = sizes[i];
        memorySet(expected_output_bytes, (int) (i + 1), expected_output_length);
        expected_output_bytes[0] = 0x45;
        expected_output_bytes[6] = expected_output_bytes[7] = 0;
        expected_output_bytes[9]                            = IP_PROTO_UDP;
        PUT_BE16(expected_output_bytes + 2, expected_output_length);
        struct pbuf sized = {.payload = expected_output_bytes, .len = sizes[i], .tot_len = sizes[i], .ref = 1};
        twfRequire(wwLwipEngineEnter(engine, &previous), "sized output engine entry");
        twfRequire(ctpNetifOutput(&ctx.netif, &sized, NULL) == ERR_OK, "sized output admission failed");
        wwLwipEngineLeave(engine, previous);
        expected_output_buffer = queued[0].args[1];
        const size_t rounded_payload =
            ((size_t) sizes[i] + kCpuLineCacheSize - 1U) / kCpuLineCacheSize * kCpuLineCacheSize;
        const size_t expected_charge = rounded_payload + 64U + sizeof(sbuf_t) + kSbufAllocationAlignment;
        twfRequire(sbufGetAllocationCharge(expected_output_buffer) == expected_charge &&
                       state->handoff_budget->bytes == expected_charge && state->handoff_budget->entries == 1,
                   "queued output grew to a pool tier or charged the wrong allocation");
        settle(&env.worker, false);
        requireEmpty(state->handoff_budget);
    }
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
        twfRequire(ctpInjectPublish(t, &key, 1, 0, msg) == ! refuse_queue, "input publication result");
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
    twfRequire(ctpInjectPublish(t, &key, 1, 0, msg), "retained input publication");
    settle(&env.worker, false);
    twfRequire(retained_pbuf != NULL && state->handoff_budget->bytes == charge && state->handoff_budget->entries == 1,
               "custom pbuf charge was released at dispatch instead of actual free");
    twfRequire(wwLwipEngineEnter(engine, &previous), "detached output engine entry");
    twfRequire(ctpNetifOutput(&ctx.netif, &p, NULL) == ERR_OK, "detached output admission failed");
    wwLwipEngineLeave(engine, previous);
    ctp_handoff_budget_t *budget = state->handoff_budget;
    observed_budget              = budget;
    budget_frees                 = 0;
    ctpHandoffBudgetDetach(budget);
    state->handoff_budget = NULL;
    tunnelDestroy(t);
    twfRequire(budget->detached && budget->entries == 2, "queued output or pbuf lost its independent budget lifetime");
    settle(&env.worker, true);
    twfRequire(budget->bytes == charge && budget->entries == 1 && budget_frees == 0,
               "late output cancellation did not release exactly its own allocation");
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
