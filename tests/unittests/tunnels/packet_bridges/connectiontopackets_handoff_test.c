/* CTest: waterwall.connectiontopackets_handoff_unit.
 * Bounded in-memory dispatch fixture: byte/entry refusal, delivery, cancellation,
 * stale flow/shutdown, and custom-pbuf retention through tunnel destruction. */
#include "ConnectionToPackets/structure.h"
#include "capacity.h"
#include "fixtures/failure/tunnel_line_failure_harness.h"
#include "fixtures/lwip/lwip_test_runtime.h"
#include "lwip/priv/tcp_priv.h"
#include "recovery_packet.h"
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
static bool         real_input;

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

static bool flowLookup(tunnel_t *t, const ctp_flow_key_t *key, wid_t *wid, uint64_t *generation)
{
    discard t;
    discard key;
    *wid        = 0;
    *generation = 1;
    return flow_alive;
}

static void drainTerminal(tunnel_t *t, wid_t wid)
{
    discard t;
    discard wid;
}

static int retainInput(ww_lwip_engine_t *engine, struct pbuf *p, struct netif *netif)
{
    if (real_input)
        return wwLwipEngineInput(engine, p, netif);
    discard engine;
    discard netif;
    twfRequire(retained_pbuf == NULL, "input replaced a retained pbuf");
    retained_pbuf = p;
    return ERR_OK;
}

static sbuf_t *createOutputBuffer(size_t length, uint16_t padding)
{
    return twfTrackAcquired(sbufCreateWithPadding(length, padding));
}

#define sendWorkerMessageForceQueueRetainOnRefusal queueRetain
#define sendWorkerMessageForceQueueWithCleanup     queueCleanup
#define ctpFlowStillOwns                           flowStillOwns
#define ctpFlowLookup                              flowLookup
#define ctpDrainTerminalLinesOnCurrentWorker       drainTerminal
#define wwLwipEngineInput                          retainInput
#define sbufCreateWithPadding                      createOutputBuffer
#include "common/netif.c"
#undef sbufCreateWithPadding
#include "downstream/payload.c"
#undef wwLwipEngineInput
#undef ctpDrainTerminalLinesOnCurrentWorker
#undef ctpFlowStillOwns
#undef ctpFlowLookup
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
    twfRequire(sbufGetInitialHeadroom(buf) >= 64 && sbufGetHeadroom(buf) >= 64,
               "queued packet lost the onward chain's padding");
    twfRequire(memcmp(sbufGetRawPtr(buf), expected_output_bytes, expected_output_length) == 0,
               "queued packet did not preserve its detached bytes");
    expected_output_buffer = NULL;
    ++output_deliveries;
    lineReuseBuffer(line, buf);
}

static void requireEmpty(ctp_handoff_budget_t *budget)
{
    twfRequire(budget->bytes == 0 && budget->entries == 0 && budget->recovery_bytes == 0 &&
                   budget->recovery_entries == 0,
               "handoff reservation leaked");
    ww_lwip_capacity_snapshot_t snapshot;
    wwLwipCapacitySnapshot(&snapshot, NULL, 0);
    twfRequire(snapshot.external_bytes == 0 && snapshot.external_recovery_bytes == 0,
               "handoff leaked its process-wide allocation charge");
}

static void makeAck(uint8_t packet[40], uint16_t destination, uint32_t sequence, uint32_t acknowledgment, uint8_t flags)
{
    memoryZero(packet, 40);
    packet[0] = 0x45;
    packet[8] = 64;
    packet[9] = IP_PROTO_TCP;
    PUT_BE16(packet + 2, 40);
    packet[12] = packet[16] = 10;
    packet[15]              = 2;
    packet[19]              = 1;
    PUT_BE16(packet + 20, 80);
    PUT_BE16(packet + 22, destination);
    PUT_BE32(packet + 24, sequence);
    PUT_BE32(packet + 28, acknowledgment);
    packet[32] = 0x50;
    packet[33] = flags;
    PUT_BE16(packet + 34, 16384);
    twfRequire(calcFullPacketChecksum(packet, 40), "ACK checksum construction");
}

static void caseRecoveryClassifier(void)
{
    uint8_t storage[42], *packet = storage + 1;
    makeAck(packet, 49152, 100, 200, TCP_ACK);
    twfRequire(wwLwipPacketIsRecovery(packet, 40, false), "unaligned ACK did not qualify");
    makeAck(packet, 49152, 100, 200, TCP_RST);
    twfRequire(wwLwipPacketIsRecovery(packet, 40, false), "RST did not qualify");
    const uint8_t rejected[] = {TCP_SYN | TCP_ACK, TCP_FIN | TCP_ACK, TCP_PSH | TCP_ACK, TCP_URG | TCP_ACK, 0};
    for (unsigned i = 0; i < ARRAY_SIZE(rejected); ++i)
    {
        makeAck(packet, 49152, 100, 200, rejected[i]);
        twfRequire(! wwLwipPacketIsRecovery(packet, 40, false), "retaining/control-creation flags used recovery");
    }
    makeAck(packet, 49152, 100, 200, TCP_ACK);
    packet[36] ^= 1;
    twfRequire(! wwLwipPacketIsRecovery(packet, 40, false) && wwLwipPacketIsRecovery(packet, 40, true),
               "checksum trust boundary changed");
    packet[32] = 0x60;
    twfRequire(! wwLwipPacketIsRecovery(packet, 40, true), "oversized TCP header used recovery");
    makeAck(packet, 49152, 100, 200, TCP_ACK);
    packet[40] = 1;
    PUT_BE16(packet + 2, 41);
    twfRequire(! wwLwipPacketIsRecovery(packet, 41, true), "TCP payload used recovery");
    makeAck(packet, 49152, 100, 200, TCP_ACK);
    packet[6] = 0x20;
    twfRequire(! wwLwipPacketIsRecovery(packet, 40, true), "fragment used recovery");
}

static err_t discardTcpOutput(struct netif *netif, struct pbuf *packet, const ip4_addr_t *destination)
{
    discard netif;
    discard packet;
    discard destination;
    return ERR_OK;
}

static err_t recoveryNetifInit(struct netif *netif)
{
    netif->output = discardTcpOutput;
    netif->mtu    = 1500;
    return ERR_OK;
}

static void caseRecoveryAckDrains(tunnel_t *t, ctp_netif_ctx_t *ctx, worker_t *worker)
{
    ctp_tstate_t *state   = tunnelGetState(t);
    state->handoff_budget = ctpHandoffBudgetCreate(16384, 32);
    ww_lwip_engine_t *previous;
    twfRequire(wwLwipEngineEnter(ctx->engine, &previous), "recovery engine entry");
    ip4_addr_t local, mask, gateway;
    IP4_ADDR(&local, 10, 0, 0, 1);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    ip4_addr_set_zero(&gateway);
    twfRequire(netif_add(&ctx->netif, &local, &mask, &gateway, ctx, recoveryNetifInit, ip_input) != NULL,
               "recovery netif creation");
    netif_set_up(&ctx->netif);
    netif_set_link_up(&ctx->netif);
    struct tcp_pcb *pcb = tcp_new();
    ip_addr_t       peer;
    IP_ADDR4(&peer, 10, 0, 0, 2);
    twfRequire(pcb != NULL && tcp_bind_netif(pcb, &ctx->netif) == ERR_OK && tcp_connect(pcb, &peer, 80, NULL) == ERR_OK,
               "recovery TCP open");
    uint8_t packet[40];
    makeAck(packet, pcb->local_port, 100, pcb->snd_nxt, TCP_SYN | TCP_ACK);
    struct pbuf *input = pbuf_alloc(PBUF_RAW, sizeof(packet), PBUF_POOL);
    twfRequire(input != NULL && pbuf_take(input, packet, sizeof(packet)) == ERR_OK, "recovery SYN ACK storage");
    twfRequire(wwLwipEngineInput(ctx->engine, input, &ctx->netif) == ERR_OK && pcb->state == ESTABLISHED,
               "recovery TCP handshake");
    const tcpwnd_size_t original_send_space = pcb->snd_buf;
    uint8_t             payload[512]        = {1};
    twfRequire(tcp_write(pcb, payload, sizeof(payload), TCP_WRITE_FLAG_COPY) == ERR_OK && tcp_output(pcb) == ERR_OK &&
                   pcb->unacked != NULL,
               "recovery queued send data");
    makeAck(packet, pcb->local_port, 101, pcb->snd_nxt, TCP_ACK);
    wwLwipEngineLeave(ctx->engine, previous);

    const size_t local_fill = state->handoff_budget->max_bytes - state->handoff_budget->recovery_max_bytes;
    bool         recovery_reserved;
    twfRequire(ctpHandoffReserveOutput(state->handoff_budget, local_fill, false, &recovery_reserved) &&
                   ! recovery_reserved,
               "fill ordinary node handoff storage");

    ww_lwip_capacity_snapshot_t snapshot;
    wwLwipCapacitySnapshot(&snapshot, NULL, 0);
    const size_t ordinary_fill = (size_t) (snapshot.config.memory_budget - snapshot.recovery_headroom -
                                           (snapshot.reserved_bytes - snapshot.recovery_bytes));
    twfRequire(wwLwipCapacityTryReserveExternal(ordinary_fill), "fill ordinary storage before ACK");
    twfRequire(ctpAllocatePacketMessage(state->handoff_budget, sizeof(packet), false) == NULL,
               "ordinary ingress bypassed full data budget");

    ctp_inject_msg_t *quota[2];
    for (unsigned i = 0; i < 2; ++i)
    {
        quota[i] = ctpAllocatePacketMessage(state->handoff_budget, sizeof(packet), true);
        twfRequire(quota[i] != NULL && quota[i]->recovery_reserved, "node recovery slot admission");
    }
    twfRequire(ctpAllocatePacketMessage(state->handoff_budget, sizeof(packet), true) == NULL &&
                   state->handoff_budget->bytes <= state->handoff_budget->max_bytes &&
                   state->handoff_budget->entries <= state->handoff_budget->max_entries,
               "node recovery exceeded reserved entry or total quota");
    for (unsigned i = 0; i < 2; ++i)
        ctpInjectMessageDestroy(quota[i]);

    /* ACK output has the same finite recovery quota. Exercise foreign cancel
     * and ordinary delivery without introducing per-packet metadata objects. */
    struct pbuf    output           = {.payload = packet, .len = sizeof(packet), .tot_len = sizeof(packet), .ref = 1};
    const unsigned saved_deliveries = output_deliveries;
    expected_output_length          = sizeof(packet);
    memoryCopy(expected_output_bytes, packet, sizeof(packet));
    for (unsigned cancel = 0; cancel < 2; ++cancel)
    {
        twfRequire(wwLwipEngineEnter(ctx->engine, &previous), "recovery output entry");
        twfRequire(ctpNetifOutput(&ctx->netif, &output, NULL) == ERR_OK && queued_count == 1 &&
                       state->handoff_budget->recovery_entries == 1,
                   "ACK output lost recovery headroom");
        wwLwipEngineLeave(ctx->engine, previous);
        expected_output_buffer = queued[0].args[1];
        settle(worker, cancel != 0);
        twfRequire(state->handoff_budget->recovery_entries == 0, "output recovery reservation leaked");
        expected_output_buffer = NULL;
    }
    output_deliveries      = saved_deliveries;
    expected_output_length = 64;
    real_input = flow_alive = true;
    state->source_ip        = local;
    sbuf_t *ack_buffer      = bufferpoolGetBestFit(worker->buffer_pool, sizeof(packet), 0);
    sbufSetLength(ack_buffer, sizeof(packet));
    memoryCopy(sbufGetMutablePtr(ack_buffer), packet, sizeof(packet));
    ctpTunnelDownStreamPayload(t, tunnelchainGetWorkerPacketLine(tunnelGetChain(t), 0), ack_buffer);
    twfRequire(queued_count == 1, "recovery ACK queue admission");
    const ctp_inject_msg_t *msg = queued[0].args[0];
    twfRequire(msg->recovery_reserved, "ACK did not use reserved compact storage");
    settle(worker, false);
    real_input = false;
    twfRequire(pcb->unacked == NULL && pcb->snd_buf == original_send_space,
               "memory pressure prevented ACK from releasing send data");
    wwLwipCapacitySnapshot(&snapshot, NULL, 0);
    twfRequire(snapshot.external_recovery_bytes == 0 && snapshot.reserved_bytes <= snapshot.config.memory_budget,
               "ACK recovery leaked its quota or exceeded aggregate budget");
    wwLwipCapacityReleaseExternal(ordinary_fill);
    ctpHandoffRelease(state->handoff_budget, local_fill);
    requireEmpty(state->handoff_budget);
    ctpHandoffBudgetDetach(state->handoff_budget);
    state->handoff_budget = NULL;
    twfRequire(wwLwipEngineEnter(ctx->engine, &previous), "recovery cleanup entry");
    tcp_abort(pcb);
    netif_remove(&ctx->netif);
    wwLwipEngineLeave(ctx->engine, previous);
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
    bool                  recovery_reserved;
    thread->admitted = ctpHandoffReserveIngress(thread->budget, 64, false, &recovery_reserved);
    twfRequire(! recovery_reserved, "ordinary concurrent reservation used recovery storage");
    int result = pthread_barrier_wait(thread->barrier);
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

static void caseProcessQuota(void)
{
    ctp_handoff_budget_t       *budget = ctpHandoffBudgetCreate(64, 1);
    ww_lwip_capacity_snapshot_t before, after;
    wwLwipCapacitySnapshot(&before, NULL, 0);
    const size_t charge =
        (size_t) (before.config.memory_budget - wwLwipCapacityRecoveryHeadroom() - before.reserved_bytes);
    twfRequire(wwLwipCapacityTryReserveExternal(charge), "could not fill global handoff capacity");
    bool recovery_reserved;
    twfRequire(! ctpHandoffReserveIngress(budget, 64, false, &recovery_reserved) && ! recovery_reserved,
               "local handoff quota bypassed global memory limit");
    wwLwipCapacitySnapshot(&after, NULL, 0);
    twfRequire(budget->bytes == 0 && budget->entries == 0 && after.external_refusals == before.external_refusals + 1,
               "global refusal leaked local quota or omitted its counter");
    wwLwipCapacityReleaseExternal(charge);
    twfRequire(ctpHandoffReserveIngress(budget, 64, false, &recovery_reserved) && ! recovery_reserved,
               "handoff did not recover after global pressure");
    ctpHandoffRelease(budget, 64);
    requireEmpty(budget);
    ctpHandoffBudgetDetach(budget);
}

int main(void)
{
    twfSetCase("CTP shared handoff admission and all terminal ownership paths");
    twfRequire(lwipTestRuntimeInitialize(), "lwIP fixture initialization failed");
    wwLwipEngineSharedInit();
    caseConcurrentQuota();
    caseProcessQuota();
    caseRecoveryClassifier();
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
    quiescenceGateInit(&state->packet_ingress_gate);
    twfRequire(quiescenceGateOpen(&state->packet_ingress_gate), "packet ingress gate did not open");
    ctp_netif_ctx_t ctx       = {.tunnel = t, .wid = 0, .engine = engine, .added = true};
    ctx.netif.state           = &ctx;
    ctp_netif_ctx_t *netifs[] = {&ctx};
    state->netifs             = netifs;
    state->netifs_count       = 1;

    caseRecoveryAckDrains(t, &ctx, &env.worker);

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
    ctp_inject_msg_t *first  = ctpAllocatePacketMessage(state->handoff_budget, 48, false);
    ctp_inject_msg_t *second = ctpAllocatePacketMessage(state->handoff_budget, 48, false);
    twfRequire(first != NULL && second != NULL && ctpAllocatePacketMessage(state->handoff_budget, 48, false) == NULL &&
                   state->handoff_budget->entries == 2 && state->handoff_budget->ingress_refused == 1,
               "input exceeded entry budget");
    ctpInjectMessageDestroy(first);
    ctpInjectMessageDestroy(second);
    requireEmpty(state->handoff_budget);

    ctp_flow_key_t key = {.protocol = IP_PROTO_TCP};
    for (unsigned mode = 0; mode < 4; ++mode)
    {
        ctp_inject_msg_t *msg = ctpAllocatePacketMessage(state->handoff_budget, 48, false);
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
    ctp_inject_msg_t *msg    = ctpAllocatePacketMessage(state->handoff_budget, 48, false);
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
