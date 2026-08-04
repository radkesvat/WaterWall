#include "IpManipulator/structure.h"
#include "TlsClient/interface.h"
#include "tricks/synfinsni/trick.h"
#include "worker_registry_fixture.h"

static test_worker_registry_t g_test_worker_registry;

enum
{
    kMaxTimedMessages = 8,
    kMaxCaptured      = 32,
    kMaxPacketLength  = 256,
    kClientAddress    = 0x0A000001,
    kClientPort       = 12345,
    kServerPort       = 443,
    kInitialSequence  = 2000
};

static const uint32_t kServerAddress = 0xC0000201U;

typedef struct timed_message_s
{
    wid_t                        wid;
    WorkerMessageCallback        callback;
    WorkerMessageCleanupCallback cleanup;
    uint32_t                     delay_ms;
    void                        *arg1;
    void                        *arg2;
    void                        *arg3;
    bool                         consumed;
} timed_message_t;

typedef struct captured_packet_s
{
    uint16_t len;
    uint8_t  bytes[kMaxPacketLength];
} captured_packet_t;

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *buffer_pool;
    tunnel_t      *t;
    tunnel_t      *sink;
    line_t        *line;
} test_env_t;

typedef struct flow_snapshot_s
{
    ipmanipulator_synfin_flow_phase_e phase;
    uint64_t                          generation;
    bool                              timer_armed;
    bool                              has_held_packet;
    bool                              exists;
} flow_snapshot_t;

static timed_message_t   timed_messages[kMaxTimedMessages];
static captured_packet_t captured_packets[kMaxCaptured];
static uint32_t          timed_message_count;
static uint32_t          captured_packet_count;
static bool              g_schedule_should_fail;

bool ipmanipulatorSynfinTestScheduleTimed(wid_t wid, WorkerMessageCallback callback,
                                          WorkerMessageCleanupCallback cleanup, uint32_t delay_ms, void *arg1,
                                          void *arg2, void *arg3);

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

bool ipmanipulatorSynfinTestScheduleTimed(wid_t wid, WorkerMessageCallback callback,
                                          WorkerMessageCleanupCallback cleanup, uint32_t delay_ms, void *arg1,
                                          void *arg2, void *arg3)
{
    if (g_schedule_should_fail)
    {
        cleanup(arg1, arg2, arg3);
        return false;
    }

    require(timed_message_count < kMaxTimedMessages, "timed-message capture overflow");
    timed_messages[timed_message_count++] = (timed_message_t) {
        .wid      = wid,
        .callback = callback,
        .cleanup  = cleanup,
        .delay_ms = delay_ms,
        .arg1     = arg1,
        .arg2     = arg2,
        .arg3     = arg3,
    };
    return true;
}

void smugglesnitrickSetFlowPassthrough(tunnel_t *t, uint32_t src_addr, uint32_t dst_addr, uint16_t src_port,
                                       uint16_t dst_port)
{
    discard t;
    discard src_addr;
    discard dst_addr;
    discard src_port;
    discard dst_port;
}

void echsnitrickSetFlowPassthrough(tunnel_t *t, uint32_t src_addr, uint32_t dst_addr, uint16_t src_port,
                                   uint16_t dst_port, uint64_t generation)
{
    discard t;
    discard src_addr;
    discard dst_addr;
    discard src_port;
    discard dst_port;
    discard generation;
}

sbuf_t *tlsclientTunnelGenerateClientHello(tunnel_t *instance, line_t *caller_line, const uint8_t *hostname,
                                           uint32_t hostname_length)
{
    discard instance;
    discard caller_line;
    discard hostname;
    discard hostname_length;
    return NULL;
}

static void captureUpstream(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;

    require(captured_packet_count < kMaxCaptured, "upstream packet capture overflow");
    captured_packet_t *capture = &captured_packets[captured_packet_count++];
    capture->len               = (uint16_t) sbufGetLength(buf);
    require(capture->len <= kMaxPacketLength, "captured packet is too large");
    memoryCopy(capture->bytes, sbufGetRawPtr(buf), capture->len);
    lineSetRecalculateChecksum(l, false);
    lineReuseBuffer(l, buf);
}

static void resetCaptures(void)
{
    memoryZero(timed_messages, sizeof(timed_messages));
    memoryZero(captured_packets, sizeof(captured_packets));
    timed_message_count    = 0;
    captured_packet_count  = 0;
    g_schedule_should_fail = false;
}

static sbuf_t *makeTcpPacket(test_env_t *env, uint32_t seq, uint8_t flags, const uint8_t *payload, uint16_t payload_len)
{
    uint16_t packet_len = (uint16_t) (sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) + payload_len);
    sbuf_t  *buf        = bufferpoolGetSmallBuffer(env->buffer_pool);
    sbufSetLength(buf, packet_len);

    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, packet_len);

    struct ip_hdr *ip = (struct ip_hdr *) packet;
    IPH_VHL_SET(ip, 4, sizeof(struct ip_hdr) / 4U);
    IPH_LEN_SET(ip, lwip_htons(packet_len));
    IPH_PROTO_SET(ip, IPPROTO_TCP);
    ip->src.addr  = lwip_htonl(kClientAddress);
    ip->dest.addr = lwip_htonl(kServerAddress);

    struct tcp_hdr *tcp = (struct tcp_hdr *) (packet + sizeof(struct ip_hdr));
    tcp->src            = lwip_htons(kClientPort);
    tcp->dest           = lwip_htons(kServerPort);
    tcp->seqno          = lwip_htonl(seq);
    TCPH_HDRLEN_FLAGS_SET(tcp, sizeof(struct tcp_hdr) / 4U, flags);

    if (payload_len > 0)
    {
        memoryCopy(packet + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr), payload, payload_len);
    }

    require(calcFullPacketChecksum(packet, packet_len), "failed to checksum a fixture packet");
    return buf;
}

static void makeCompleteClientHello(uint8_t payload[43])
{
    memoryZero(payload, 43);
    payload[0] = 0x16;
    payload[1] = 0x03;
    payload[2] = 0x03;
    payload[3] = 0x00;
    payload[4] = 38;
    payload[5] = 0x01;
    payload[6] = 0x00;
    payload[7] = 0x00;
    payload[8] = 34;
}

static void makeFragmentedClientHelloPrefix(uint8_t payload[20])
{
    memoryZero(payload, 20);
    payload[0] = 0x16;
    payload[1] = 0x03;
    payload[2] = 0x03;
    payload[3] = 0x00;
    payload[4] = 59;
    payload[5] = 0x01;
    payload[6] = 0x00;
    payload[7] = 0x00;
    payload[8] = 55;
}

static void sendUpstream(test_env_t *env, uint32_t seq, uint8_t flags, const uint8_t *payload, uint16_t payload_len)
{
    sbuf_t *buf = makeTcpPacket(env, seq, flags, payload, payload_len);
    require(synfinsnitrickUpStreamPayload(env->t, env->line, buf), "synfin-sni did not consume a fixture packet");
}

static void warmFlow(test_env_t *env)
{
    sendUpstream(env, kInitialSequence, TCP_SYN, NULL, 0);
    sendUpstream(env, kInitialSequence + 1U, TCP_ACK, NULL, 0);
    require(captured_packet_count == 2, "synfin-sni warmup packets were not forwarded");
}

static flow_snapshot_t snapshotFlow(test_env_t *env)
{
    ipmanipulator_tstate_t  *state = tunnelGetState(env->t);
    ipmanipulator_flow_key_t key =
        ipmanipulatorFlowKeyMake(lwip_htonl(kClientAddress), kClientPort, lwip_htonl(kServerAddress), kServerPort);
    ipmanipulator_flow_shard_t *shard  = ipmanipulatorFlowTableLockShard(&state->synfin_table, &key);
    flow_snapshot_t             result = {0};

    require(shard != NULL, "synfin-sni flow table is unavailable");
    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->synfin_table, shard, &key);
    if (entry != NULL)
    {
        ipmanipulator_synfin_flow_t *flow = ipmanipulatorFlowEntryRecord(entry);
        result                            = (flow_snapshot_t) {
                                       .phase           = flow->phase,
                                       .generation      = flow->hold_generation,
                                       .timer_armed     = flow->hold_timer_armed,
                                       .has_held_packet = flow->held_packet.buf != NULL,
                                       .exists          = true,
        };
    }
    ipmanipulatorFlowShardUnlock(shard);
    return result;
}

static void fireTimedMessage(uint32_t index)
{
    require(index < timed_message_count && ! timed_messages[index].consumed, "invalid timed-message callback");
    timed_message_t *message = &timed_messages[index];
    message->consumed        = true;
    message->callback(NULL, message->arg1, message->arg2, message->arg3);
}

static void cleanupTimedMessage(uint32_t index)
{
    require(index < timed_message_count && ! timed_messages[index].consumed, "invalid timed-message cleanup");
    timed_message_t *message = &timed_messages[index];
    message->consumed        = true;
    message->cleanup(message->arg1, message->arg2, message->arg3);
}

static void setupEnv(test_env_t *env)
{
    memoryZero(env, sizeof(*env));
    resetCaptures();

    env->large_master                    = masterpoolCreateWithCapacity(64);
    env->small_master                    = masterpoolCreateWithCapacity(64);
    env->buffer_pool                     = bufferpoolCreate(env->large_master, env->small_master, 64, 4096, 512);
    GSTATE.shortcut_buffer_pools         = &env->buffer_pool;
    GSTATE.masterpool_buffer_pools_large = env->large_master;
    GSTATE.masterpool_buffer_pools_small = env->small_master;

    env->line = memoryAllocateZero(sizeof(*env->line));
    require(env->line != NULL, "failed to allocate the synfin-sni test line");
    atomicStoreRelaxed(&env->line->refc, 1);
    env->line->alive = true;
    env->line->wid   = 0;

    static node_t node = {.name = (char *) "ipmanipulator-synfin-hold-test", .type = (char *) "TestTunnel"};
    env->t             = tunnelCreate(&node, sizeof(ipmanipulator_tstate_t), 0);
    env->sink          = tunnelCreate(&node, 0, 0);
    require(env->t != NULL && env->sink != NULL, "failed to create synfin-sni test tunnels");
    env->t->next          = env->sink;
    env->sink->prev       = env->t;
    env->sink->fnPayloadU = captureUpstream;

    ipmanipulator_tstate_t *state           = tunnelGetState(env->t);
    state->trick_stateful_flow_limit        = kIpManipulatorFlowLimitMin;
    state->trick_synfin_sni                 = true;
    state->trick_synfin_sni_hold_timeout_ms = 50;
    atomicStoreU64Relaxed(&state->delay_barrier_next_generation, 0);
    require(synfinsnitrickInitializeState(env->t), "failed to initialize synfin-sni flow state");
}

static void destroyEnv(test_env_t *env)
{
    for (uint32_t i = 0; i < timed_message_count; ++i)
    {
        if (! timed_messages[i].consumed)
        {
            cleanupTimedMessage(i);
        }
    }

    synfinsnitrickDestroyState(env->t);
    require(atomicLoadRelaxed(&env->line->refc) == 1, "synfin-sni leaked a line reference");
    tunnelDestroy(env->sink);
    tunnelDestroy(env->t);
    memoryFree(env->line);

    GSTATE.shortcut_buffer_pools         = NULL;
    GSTATE.masterpool_buffer_pools_large = NULL;
    GSTATE.masterpool_buffer_pools_small = NULL;
    bufferpoolDestroy(env->buffer_pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

static void testCompleteAndNonTlsPayloadsPassImmediately(void)
{
    test_env_t env;
    setupEnv(&env);
    warmFlow(&env);

    uint8_t complete[43];
    makeCompleteClientHello(complete);
    sendUpstream(&env, kInitialSequence + 1U, TCP_ACK | TCP_PSH, complete, sizeof(complete));
    require(captured_packet_count == 3 && timed_message_count == 0, "complete ClientHello was held or armed a timer");
    require(snapshotFlow(&env).phase == kIpManipulatorSynfinFlowPhasePassthrough,
            "complete ClientHello did not select passthrough");
    destroyEnv(&env);

    setupEnv(&env);
    warmFlow(&env);
    static const uint8_t http[] = "GET / HTTP/1.0\r\n\r\n";
    sendUpstream(&env, kInitialSequence + 1U, TCP_ACK | TCP_PSH, http, sizeof(http) - 1U);
    require(captured_packet_count == 3 && timed_message_count == 0, "non-TLS first payload was held or armed a timer");
    require(snapshotFlow(&env).phase == kIpManipulatorSynfinFlowPhasePassthrough,
            "non-TLS first payload did not select passthrough");
    destroyEnv(&env);
}

static void testFragmentedHoldCancelsOnSecondSegment(void)
{
    test_env_t env;
    setupEnv(&env);
    warmFlow(&env);

    uint8_t first[20];
    uint8_t second[44];
    makeFragmentedClientHelloPrefix(first);
    memorySet(second, 0x5A, sizeof(second));
    sendUpstream(&env, kInitialSequence + 1U, TCP_ACK, first, sizeof(first));

    flow_snapshot_t held = snapshotFlow(&env);
    require(captured_packet_count == 2 && timed_message_count == 1 && timed_messages[0].delay_ms == 50 &&
                timed_messages[0].wid == 0,
            "fragmented ClientHello did not arm a worker-local hold timer");
    require(held.phase == kIpManipulatorSynfinFlowPhaseHoldThird && held.timer_armed && held.has_held_packet &&
                held.generation != 0,
            "fragmented ClientHello hold state is incomplete");

    sendUpstream(&env, kInitialSequence + 1U + sizeof(first), TCP_ACK, second, sizeof(second));
    require(captured_packet_count == 4, "second segment did not release held and current packets");
    require(snapshotFlow(&env).phase == kIpManipulatorSynfinFlowPhasePassthrough,
            "second segment did not cancel the hold");
    fireTimedMessage(0);
    require(captured_packet_count == 4, "stale timer forwarded the canceled hold");
    destroyEnv(&env);
}

static void testTimeoutFailsOpenAndPreservesPayload(void)
{
    test_env_t env;
    setupEnv(&env);
    warmFlow(&env);

    uint8_t first[20];
    makeFragmentedClientHelloPrefix(first);
    sendUpstream(&env, kInitialSequence + 1U, TCP_ACK, first, sizeof(first));
    fireTimedMessage(0);

    flow_snapshot_t flow = snapshotFlow(&env);
    require(captured_packet_count == 3, "hold timeout did not forward the retained segment");
    require(flow.phase == kIpManipulatorSynfinFlowPhasePassthrough && ! flow.timer_armed && ! flow.has_held_packet,
            "hold timeout did not fail open");
    require(memoryCompare(
                captured_packets[2].bytes + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr), first, sizeof(first)) == 0,
            "hold timeout changed the retained payload");

    static const uint8_t later[] = "later";
    sendUpstream(&env, kInitialSequence + 1U + sizeof(first), TCP_ACK, later, sizeof(later));
    require(captured_packet_count == 4, "post-timeout payload did not pass through");
    destroyEnv(&env);
}

static void testDeadLineTimeoutRecycles(void)
{
    test_env_t env;
    setupEnv(&env);
    warmFlow(&env);

    uint8_t first[20];
    makeFragmentedClientHelloPrefix(first);
    sendUpstream(&env, kInitialSequence + 1U, TCP_ACK, first, sizeof(first));
    env.line->alive = false;
    fireTimedMessage(0);

    require(captured_packet_count == 2, "dead-line hold timeout forwarded a packet");
    require(snapshotFlow(&env).phase == kIpManipulatorSynfinFlowPhasePassthrough,
            "dead-line hold timeout did not clear the hold");
    require(atomicLoadRelaxed(&env.line->refc) == 1, "dead-line hold timeout leaked a line reference");
    destroyEnv(&env);
}

static void testStaleGenerationAndCleanup(void)
{
    test_env_t env;
    setupEnv(&env);
    warmFlow(&env);

    uint8_t first[20];
    makeFragmentedClientHelloPrefix(first);
    sendUpstream(&env, kInitialSequence + 1U, TCP_ACK, first, sizeof(first));
    uint64_t first_generation = snapshotFlow(&env).generation;

    sendUpstream(&env, kInitialSequence + 100U, TCP_SYN, NULL, 0);
    sendUpstream(&env, kInitialSequence + 101U, TCP_ACK, NULL, 0);
    sendUpstream(&env, kInitialSequence + 101U, TCP_ACK, first, sizeof(first));
    flow_snapshot_t replacement = snapshotFlow(&env);
    require(timed_message_count == 2 && replacement.generation != first_generation,
            "replacement hold reused its generation");

    uint32_t before_stale = captured_packet_count;
    fireTimedMessage(0);
    flow_snapshot_t after_stale = snapshotFlow(&env);
    require(captured_packet_count == before_stale && after_stale.generation == replacement.generation &&
                after_stale.phase == kIpManipulatorSynfinFlowPhaseHoldThird && after_stale.has_held_packet,
            "old-generation timer altered the replacement hold");

    require(atomicLoadRelaxed(&env.line->refc) == 3, "replacement hold and timer references are unbalanced");
    cleanupTimedMessage(1);
    require(atomicLoadRelaxed(&env.line->refc) == 1, "timer cleanup leaked the record's retained reference");
    require(snapshotFlow(&env).phase == kIpManipulatorSynfinFlowPhasePassthrough,
            "target-worker timer cleanup did not fail open");
    require(captured_packet_count == before_stale + 1U, "target-worker timer cleanup did not release the held segment");
    destroyEnv(&env);
}

static void testDroppedScheduleReleasesHold(void)
{
    test_env_t env;
    setupEnv(&env);
    warmFlow(&env);

    uint8_t first[20];
    makeFragmentedClientHelloPrefix(first);
    g_schedule_should_fail = true;
    sendUpstream(&env, kInitialSequence + 1U, TCP_ACK, first, sizeof(first));

    flow_snapshot_t flow = snapshotFlow(&env);
    require(timed_message_count == 0, "a rejected synfin hold schedule was recorded as accepted");
    require(captured_packet_count == 3, "a rejected synfin hold schedule did not release the segment");
    require(flow.phase == kIpManipulatorSynfinFlowPhasePassthrough && ! flow.timer_armed && ! flow.has_held_packet,
            "a rejected synfin hold schedule left the flow held");
    require(atomicLoadRelaxed(&env.line->refc) == 1, "rejected synfin hold scheduling leaked a line reference");
    destroyEnv(&env);
}

int main(void)
{
    const uint32_t saved_workers_count = GSTATE.workers_count;

    GSTATE.workers_count = 1;
    testWorkerRegistryInstall(&g_test_worker_registry);
    testWorkerBindWID(0);
    checkSumInit();
    require(globalstateInitializeSecureRandom(), "the operating system random source is unavailable");

    testCompleteAndNonTlsPayloadsPassImmediately();
    testFragmentedHoldCancelsOnSecondSegment();
    testTimeoutFailsOpenAndPreservesPayload();
    testDeadLineTimeoutRecycles();
    testStaleGenerationAndCleanup();
    testDroppedScheduleReleasesHold();

    globalstateDestroySecureRandom();
    GSTATE.workers_count = saved_workers_count;
    testWorkerRegistryRestore(&g_test_worker_registry);
    printf("ALL unit tests passed!\n");
    return 0;
}
