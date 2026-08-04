#include "IpManipulator/structure.h"
#include "devices/device_flow_affinity.h"
#include "tricks/portghost/trick.h"
#include "tricks/protoswap/trick.h"
#include "tricks/smugglefin/trick.h"
#include "worker_registry_fixture.h"

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

enum
{
    kMaxTimedMessages                = 16,
    kMaxImmediateMessages            = 16,
    kExpectedSmuggleFinQueueCapacity = 256
};

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

typedef struct immediate_message_s
{
    wid_t                        wid;
    WorkerMessageCallback        callback;
    WorkerMessageCleanupCallback cleanup;
    void                        *arg1;
    void                        *arg2;
    void                        *arg3;
    bool                         consumed;
} immediate_message_t;

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *buffer_pools[2];
} test_env_t;

static timed_message_t     timed_messages[kMaxTimedMessages];
static immediate_message_t immediate_messages[kMaxImmediateMessages];
static uint32_t            timed_message_count;
static uint32_t            immediate_message_count;
static uint32_t            normal_upstream_packets;
static uint32_t            normal_downstream_packets;
static uint32_t            downstream_entry_packets;
static uint32_t            downstream_after_smuggle_fin_packets;
static uint32_t            mirrored_fin_packets;
static uint32_t            replayed_upstream_sequences[kExpectedSmuggleFinQueueCapacity];
static bool                replayed_upstream_checksum_intents[kExpectedSmuggleFinQueueCapacity];
static uint32_t            replayed_downstream_sequences[kExpectedSmuggleFinQueueCapacity];
static bool                replayed_downstream_checksum_intents[kExpectedSmuggleFinQueueCapacity];
static uint8_t             replayed_downstream_protocols[kExpectedSmuggleFinQueueCapacity];
static uint16_t            replayed_downstream_src_ports[kExpectedSmuggleFinQueueCapacity];
static uint16_t            replayed_downstream_dst_ports[kExpectedSmuggleFinQueueCapacity];
static uint32_t            replayed_downstream_packet_lengths[kExpectedSmuggleFinQueueCapacity];
static uint8_t             replay_directions[kExpectedSmuggleFinQueueCapacity * 2U];
static uint32_t            replay_sequences[kExpectedSmuggleFinQueueCapacity * 2U];
static uint32_t            replay_count;
static bool                reject_immediate_messages;
static bool                g_schedule_should_fail;

bool ipmanipulatorSmuggleFinTestScheduleTimed(wid_t wid, WorkerMessageCallback callback,
                                              WorkerMessageCleanupCallback cleanup, uint32_t delay_ms, void *arg1,
                                              void *arg2, void *arg3);
bool ipmanipulatorSmuggleFinTestScheduleImmediate(wid_t wid, WorkerMessageCallback callback,
                                                  WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2,
                                                  void *arg3);

uint8_t ipmanipulatorResolveTransportProtocol(const ipmanipulator_tstate_t *state, uint8_t packet_protocol)
{
    if (packet_protocol == state->trick_proto_swap_tcp_number)
    {
        return IPPROTO_TCP;
    }

    if (packet_protocol == state->trick_proto_swap_udp_number)
    {
        return IPPROTO_UDP;
    }

    return packet_protocol == IPPROTO_TCP || packet_protocol == IPPROTO_UDP ? packet_protocol : 0;
}

bool ipmanipulatorShouldLogEgressWarning(ipmanipulator_tstate_t *state)
{
    discard state;
    return true;
}

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

bool ipmanipulatorSmuggleFinTestScheduleTimed(wid_t wid, WorkerMessageCallback callback,
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

bool ipmanipulatorSmuggleFinTestScheduleImmediate(wid_t wid, WorkerMessageCallback callback,
                                                  WorkerMessageCleanupCallback cleanup, void *arg1, void *arg2,
                                                  void *arg3)
{
    if (reject_immediate_messages)
    {
        cleanup(arg1, arg2, arg3);
        return false;
    }

    require(immediate_message_count < kMaxImmediateMessages, "immediate-message capture overflow");
    immediate_messages[immediate_message_count++] = (immediate_message_t) {
        .wid      = wid,
        .callback = callback,
        .cleanup  = cleanup,
        .arg1     = arg1,
        .arg2     = arg2,
        .arg3     = arg3,
    };
    return true;
}

void ipmanipulatorUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard               t;
    const uint8_t        *packet     = (const uint8_t *) sbufGetRawPtr(buf);
    const struct ip_hdr  *ipheader   = (const struct ip_hdr *) packet;
    const struct tcp_hdr *tcp_header = (const struct tcp_hdr *) (packet + IPH_HL_BYTES(ipheader));

    require(normal_upstream_packets < kExpectedSmuggleFinQueueCapacity, "upstream replay capture overflow");
    replayed_upstream_sequences[normal_upstream_packets]        = lwip_ntohl(tcp_header->seqno);
    replayed_upstream_checksum_intents[normal_upstream_packets] = lineGetRecalculateChecksum(l);
    if (lineGetRecalculateChecksum(l))
    {
        require(calcFullPacketChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf)),
                "upstream sink failed to apply the queued checksum request");
        require(tcp_header->chksum != 0, "upstream sink left a requested TCP checksum empty");
    }
    normal_upstream_packets++;
    require(replay_count < ARRAY_SIZE(replay_directions), "replay-order capture overflow");
    replay_directions[replay_count] = 0;
    replay_sequences[replay_count]  = lwip_ntohl(tcp_header->seqno);
    replay_count++;
    lineSetRecalculateChecksum(l, false);
    lineReuseBuffer(l, buf);
}

void ipmanipulatorDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    downstream_entry_packets++;
    normal_downstream_packets++;
    lineSetRecalculateChecksum(l, false);
    lineReuseBuffer(l, buf);
}

void ipmanipulatorDownStreamPayloadAfterSmuggleFin(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;

    const uint8_t        *packet     = (const uint8_t *) sbufGetRawPtr(buf);
    const struct ip_hdr  *ipheader   = (const struct ip_hdr *) packet;
    const struct tcp_hdr *tcp_header = (const struct tcp_hdr *) (packet + IPH_HL_BYTES(ipheader));

    require(downstream_after_smuggle_fin_packets < kExpectedSmuggleFinQueueCapacity,
            "downstream replay capture overflow");
    replayed_downstream_sequences[downstream_after_smuggle_fin_packets]        = lwip_ntohl(tcp_header->seqno);
    replayed_downstream_checksum_intents[downstream_after_smuggle_fin_packets] = lineGetRecalculateChecksum(l);
    replayed_downstream_protocols[downstream_after_smuggle_fin_packets]        = IPH_PROTO(ipheader);
    replayed_downstream_src_ports[downstream_after_smuggle_fin_packets]        = lwip_ntohs(tcp_header->src);
    replayed_downstream_dst_ports[downstream_after_smuggle_fin_packets]        = lwip_ntohs(tcp_header->dest);
    replayed_downstream_packet_lengths[downstream_after_smuggle_fin_packets]   = sbufGetLength(buf);
    if (lineGetRecalculateChecksum(l))
    {
        require(calcFullPacketChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf)),
                "downstream sink failed to apply the queued checksum request");
        require(tcp_header->chksum != 0, "downstream sink left a requested TCP checksum empty");
    }

    downstream_after_smuggle_fin_packets++;
    normal_downstream_packets++;
    require(replay_count < ARRAY_SIZE(replay_directions), "replay-order capture overflow");
    replay_directions[replay_count] = 1;
    replay_sequences[replay_count]  = lwip_ntohl(tcp_header->seqno);
    replay_count++;
    lineSetRecalculateChecksum(l, false);
    lineReuseBuffer(l, buf);
}

sbuf_t *clonePacketWithLength(line_t *l, sbuf_t *buf, uint32_t new_len)
{
    buffer_pool_t *pool  = lineGetBufferPool(l);
    sbuf_t        *clone = NULL;

    if (new_len <= bufferpoolGetSmallBufferSize(pool))
    {
        clone = bufferpoolGetSmallBuffer(pool);
    }
    else if (new_len <= bufferpoolGetLargeBufferSize(pool))
    {
        clone = bufferpoolGetLargeBuffer(pool);
    }
    else
    {
        clone = sbufCreateWithPadding(new_len, sbufGetLeftPadding(buf));
    }

    sbufSetLength(clone, new_len);
    return clone;
}

void ipmanipulatorEmitUpstreamPreservingTuple(tunnel_t *t, line_t *l, sbuf_t *buf, LineTaskFnWithBuf forward)
{
    forward(t, l, buf);
}

static void receiveMirroredFin(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    mirrored_fin_packets++;
    lineReuseBuffer(l, buf);
}

static void envSetup(test_env_t *env)
{
    memoryZero(env, sizeof(*env));
    env->large_master    = masterpoolCreateWithCapacity(64);
    env->small_master    = masterpoolCreateWithCapacity(64);
    env->buffer_pools[0] = bufferpoolCreate(env->large_master, env->small_master, 64, 8192, 4096);
    env->buffer_pools[1] = bufferpoolCreate(env->large_master, env->small_master, 64, 8192, 4096);

    GSTATE.shortcut_buffer_pools         = env->buffer_pools;
    GSTATE.masterpool_buffer_pools_large = env->large_master;
    GSTATE.masterpool_buffer_pools_small = env->small_master;
    GSTATE.workers_count                 = 3;
    testWorkerRegistryInstall(&g_test_worker_registry);
    testWorkerBindWID(0);

    /* Bounded flow tables refuse to run without a secure hash seed. */
    require(globalstateInitializeSecureRandom(), "the operating system random source is unavailable");
}

static void envTeardown(test_env_t *env)
{
    GSTATE.shortcut_buffer_pools         = NULL;
    GSTATE.masterpool_buffer_pools_large = NULL;
    GSTATE.masterpool_buffer_pools_small = NULL;
    globalstateDestroySecureRandom();
    GSTATE.workers_count = 0;
    testWorkerRegistryRestore(&g_test_worker_registry);

    bufferpoolDestroy(env->buffer_pools[0]);
    bufferpoolDestroy(env->buffer_pools[1]);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

static void initializeLine(line_t *line, wid_t wid)
{
    memoryZero(line, sizeof(*line));
    atomicStoreRelaxed(&line->refc, 1);
    line->alive = true;
    line->wid   = wid;
}

static sbuf_t *makeTcpPacket(wid_t wid, uint32_t src_addr, uint16_t src_port, uint32_t dst_addr, uint16_t dst_port,
                             uint32_t seq, uint32_t ack, uint8_t flags, uint16_t payload_len)
{
    uint16_t packet_len = (uint16_t) (sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) + payload_len);
    sbuf_t  *buf        = bufferpoolGetSmallBuffer(getWorkerBufferPool(wid));
    sbufSetLength(buf, packet_len);

    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, packet_len);

    struct ip_hdr *ip = (struct ip_hdr *) packet;
    IPH_VHL_SET(ip, 4, sizeof(struct ip_hdr) / 4U);
    IPH_LEN_SET(ip, lwip_htons(packet_len));
    IPH_PROTO_SET(ip, IPPROTO_TCP);
    ip->src.addr  = lwip_htonl(src_addr);
    ip->dest.addr = lwip_htonl(dst_addr);

    struct tcp_hdr *tcp = (struct tcp_hdr *) (packet + sizeof(struct ip_hdr));
    tcp->src            = lwip_htons(src_port);
    tcp->dest           = lwip_htons(dst_port);
    tcp->seqno          = lwip_htonl(seq);
    tcp->ackno          = lwip_htonl(ack);
    TCPH_HDRLEN_FLAGS_SET(tcp, sizeof(struct tcp_hdr) / 4U, flags);

    if (payload_len > 0)
    {
        memorySet(packet + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr), 0x5A, payload_len);
    }

    return buf;
}

static tunnel_t *createTestTunnel(tunnel_t *normal_upstream, tunnel_t *normal_downstream, tunnel_t *fin_branch)
{
    static char   real_name[] = "fin-branch";
    static node_t real_node   = {.name = real_name};

    tunnel_t *t = memoryAllocateAlignedZero(sizeof(tunnel_t) + sizeof(ipmanipulator_tstate_t), kCpuLineCacheSize);
    require(t != NULL, "failed to allocate test tunnel");

    t->tstate_size                            = sizeof(ipmanipulator_tstate_t);
    t->next                                   = normal_upstream;
    t->prev                                   = normal_downstream;
    fin_branch->fnPayloadU                    = receiveMirroredFin;
    ipmanipulator_tstate_t *state             = tunnelGetState(t);
    state->trick_smuggle_fin                  = true;
    state->trick_smuggle_fin_delay_ms         = 0;
    state->trick_smuggle_fin_pause_timeout_ms = 25;
    state->trick_real_fin_upstream_node       = &real_node;
    state->trick_real_fin_upstream_tunnel     = fin_branch;
    state->trick_stateful_flow_limit          = kIpManipulatorFlowLimitMin;
    require(smugglefintrickInitializeState(t), "failed to create the smuggle-fin flow table");
    return t;
}

/*
 * Test-only accessor for one bounded flow record. Production code may only use
 * an entry pointer while its shard is locked; these tests are single threaded,
 * so the record stays put until the entry is removed.
 */
static ipmanipulator_smuggle_fin_flow_t *findFinFlow(ipmanipulator_tstate_t *state, uint32_t src_addr,
                                                     uint16_t src_port, uint32_t dst_addr, uint16_t dst_port)
{
    ipmanipulator_flow_key_t key =
        ipmanipulatorFlowKeyMake(lwip_htonl(src_addr), src_port, lwip_htonl(dst_addr), dst_port);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->smuggle_fin_table, &key);

    if (shard == NULL)
    {
        return NULL;
    }

    ipmanipulator_flow_entry_t       *entry = ipmanipulatorFlowShardFind(&state->smuggle_fin_table, shard, &key);
    ipmanipulator_smuggle_fin_flow_t *flow =
        entry != NULL ? (ipmanipulator_smuggle_fin_flow_t *) ipmanipulatorFlowEntryRecord(entry) : NULL;

    ipmanipulatorFlowShardUnlock(shard);
    return flow;
}

/* The tuple every fixture in this file pauses. */
static ipmanipulator_smuggle_fin_flow_t *findPausedFixtureFlow(ipmanipulator_tstate_t *state)
{
    return findFinFlow(state, 0x0A000001, 12345, 0xC0000201, 443);
}

/* Forces the bounded-table idle deadline for one tuple into the past. */
static void expireFinFlowNow(ipmanipulator_tstate_t *state, uint32_t src_addr, uint16_t src_port, uint32_t dst_addr,
                             uint16_t dst_port)
{
    ipmanipulator_flow_key_t key =
        ipmanipulatorFlowKeyMake(lwip_htonl(src_addr), src_port, lwip_htonl(dst_addr), dst_port);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->smuggle_fin_table, &key);

    require(shard != NULL, "the smuggle-fin flow table is not ready");

    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->smuggle_fin_table, shard, &key);
    require(entry != NULL, "the flow to expire is not in the table");
    ipmanipulatorFlowShardTouch(shard, entry, 0);

    ipmanipulatorFlowShardUnlock(shard);
}

/*
 * Admits a record directly so a test can plant a stale flow. Expiry is shard
 * local, so the fixture and the packet that triggers cleanup share a tuple.
 */
static ipmanipulator_smuggle_fin_flow_t *insertFinFlow(ipmanipulator_tstate_t *state, uint32_t src_addr,
                                                       uint16_t src_port, uint32_t dst_addr, uint16_t dst_port)
{
    ipmanipulator_flow_key_t key =
        ipmanipulatorFlowKeyMake(lwip_htonl(src_addr), src_port, lwip_htonl(dst_addr), dst_port);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->smuggle_fin_table, &key);

    require(shard != NULL, "the smuggle-fin flow table is not ready");

    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardReserve(&state->smuggle_fin_table, shard, &key, 0, 0);
    require(entry != NULL, "failed to admit a fixture flow");

    ipmanipulator_smuggle_fin_flow_t *flow = (ipmanipulator_smuggle_fin_flow_t *) ipmanipulatorFlowEntryRecord(entry);

    flow->src_addr = lwip_htonl(src_addr);
    flow->dst_addr = lwip_htonl(dst_addr);
    flow->src_port = src_port;
    flow->dst_port = dst_port;

    ipmanipulatorFlowShardUnlock(shard);
    return flow;
}

static void cleanupTimedMessages(void)
{
    for (uint32_t i = 0; i < timed_message_count; ++i)
    {
        timed_message_t *message = &timed_messages[i];
        if (! message->consumed)
        {
            message->cleanup(message->arg1, message->arg2, message->arg3);
            message->consumed = true;
        }
    }
}

static void cleanupImmediateMessages(void)
{
    for (uint32_t i = 0; i < immediate_message_count; ++i)
    {
        immediate_message_t *message = &immediate_messages[i];
        if (! message->consumed)
        {
            message->cleanup(message->arg1, message->arg2, message->arg3);
            message->consumed = true;
        }
    }
}

static void destroyTestTunnel(tunnel_t *t)
{
    cleanupImmediateMessages();
    cleanupTimedMessages();
    smugglefintrickDestroyState(t);
    memoryFreeAligned(t);
}

static void resetCounters(void)
{
    memoryZero(timed_messages, sizeof(timed_messages));
    memoryZero(immediate_messages, sizeof(immediate_messages));
    timed_message_count                  = 0;
    immediate_message_count              = 0;
    normal_upstream_packets              = 0;
    normal_downstream_packets            = 0;
    downstream_entry_packets             = 0;
    downstream_after_smuggle_fin_packets = 0;
    mirrored_fin_packets                 = 0;
    replay_count                         = 0;
    reject_immediate_messages            = false;
    g_schedule_should_fail               = false;
    memoryZero(replayed_upstream_sequences, sizeof(replayed_upstream_sequences));
    memoryZero(replayed_upstream_checksum_intents, sizeof(replayed_upstream_checksum_intents));
    memoryZero(replayed_downstream_sequences, sizeof(replayed_downstream_sequences));
    memoryZero(replayed_downstream_checksum_intents, sizeof(replayed_downstream_checksum_intents));
    memoryZero(replayed_downstream_protocols, sizeof(replayed_downstream_protocols));
    memoryZero(replayed_downstream_src_ports, sizeof(replayed_downstream_src_ports));
    memoryZero(replayed_downstream_dst_ports, sizeof(replayed_downstream_dst_ports));
    memoryZero(replayed_downstream_packet_lengths, sizeof(replayed_downstream_packet_lengths));
    memoryZero(replay_directions, sizeof(replay_directions));
    memoryZero(replay_sequences, sizeof(replay_sequences));
}

static void runTimedMessage(uint32_t index)
{
    require(index < timed_message_count, "timed-message index is out of range");
    timed_message_t *message = &timed_messages[index];
    require(! message->consumed, "timed message ran twice");

    testWorkerBindWID(message->wid);
    worker_t worker = {.wid = message->wid};
    message->callback(&worker, message->arg1, message->arg2, message->arg3);
    message->consumed = true;
}

static void runImmediateMessage(uint32_t index)
{
    require(index < immediate_message_count, "immediate-message index is out of range");
    immediate_message_t *message = &immediate_messages[index];
    require(! message->consumed, "immediate message ran twice");

    testWorkerBindWID(message->wid);
    worker_t worker = {.wid = message->wid};
    message->callback(&worker, message->arg1, message->arg2, message->arg3);
    message->consumed = true;
}

static void cancelImmediateMessage(uint32_t index)
{
    require(index < immediate_message_count, "immediate-message cancellation index is out of range");
    immediate_message_t *message = &immediate_messages[index];
    require(! message->consumed, "immediate message was already consumed");

    message->cleanup(message->arg1, message->arg2, message->arg3);
    message->consumed = true;
}

static void startPausedFlowForTuple(tunnel_t *t, line_t *line, uint32_t src_addr, uint16_t src_port, uint32_t dst_addr,
                                    uint16_t dst_port)
{
    bool     expected_recalculate_checksum = lineGetRecalculateChecksum(line);
    uint32_t previous_mirrored_fin_packets = mirrored_fin_packets;
    uint32_t previous_timed_message_count  = timed_message_count;
    sbuf_t  *packet = makeTcpPacket(line->wid, src_addr, src_port, dst_addr, dst_port, 100, 200, TCP_ACK | TCP_PSH, 10);
    require(smugglefintrickUpStreamPayload(t, line, packet), "first payload did not pause its flow");

    ipmanipulator_tstate_t           *state = tunnelGetState(t);
    ipmanipulator_smuggle_fin_flow_t *flow  = findFinFlow(state, src_addr, src_port, dst_addr, dst_port);
    require(flow != NULL, "the paused flow is missing from the bounded table");
    require(flow->queued_packets_count == 1, "first payload was not queued");
    require(flow->queued_packets[0].recalculate_checksum == expected_recalculate_checksum,
            "first payload did not retain its checksum intent");
    require(! lineGetRecalculateChecksum(line), "queued first payload left checksum intent on the packet line");
    require(mirrored_fin_packets == previous_mirrored_fin_packets + 1, "mirrored FIN was not sent");
    require(timed_message_count == previous_timed_message_count + 1, "pause timeout was not scheduled");
}

static void startPausedFlow(tunnel_t *t, line_t *line)
{
    startPausedFlowForTuple(t, line, 0x0A000001, 12345, 0xC0000201, 443);
}

static void testUnrelatedFlowPasses(void)
{
    tunnel_t  normal_upstream   = {0};
    tunnel_t  normal_downstream = {0};
    tunnel_t  fin_branch        = {0};
    tunnel_t *t                 = createTestTunnel(&normal_upstream, &normal_downstream, &fin_branch);
    line_t    line;
    initializeLine(&line, 0);

    resetCounters();
    startPausedFlow(t, &line);

    sbuf_t *unrelated = makeTcpPacket(0, 0x0A000002, 23456, 0xC0000202, 443, 300, 400, TCP_ACK | TCP_PSH, 12);
    require(! smugglefintrickUpStreamPayload(t, &line, unrelated), "unrelated flow was consumed by smuggle-fin");
    ipmanipulatorUpStreamPayload(t, &line, unrelated);
    require(normal_upstream_packets == 1, "unrelated flow was held behind the paused flow");

    sbuf_t *unrelated_reverse = makeTcpPacket(0, 0xC0000202, 443, 0x0A000002, 23456, 400, 312, TCP_ACK | TCP_PSH, 12);
    require(! smugglefintrickDownStreamPayload(t, &line, unrelated_reverse),
            "unrelated reverse flow was consumed by smuggle-fin");
    ipmanipulatorDownStreamPayload(t, &line, unrelated_reverse);
    require(normal_downstream_packets == 1, "unrelated reverse flow was held behind the paused flow");

    runTimedMessage(0);
    require(normal_upstream_packets == 2, "paused flow was not released by its timeout");
    destroyTestTunnel(t);
}

static void testPauseTimeoutReleasesFlow(void)
{
    tunnel_t  normal_upstream   = {0};
    tunnel_t  normal_downstream = {0};
    tunnel_t  fin_branch        = {0};
    tunnel_t *t                 = createTestTunnel(&normal_upstream, &normal_downstream, &fin_branch);
    line_t    line;
    initializeLine(&line, 0);

    resetCounters();
    startPausedFlow(t, &line);
    require(timed_messages[0].delay_ms == 25, "pause timeout used the wrong delay");

    sbuf_t *second = makeTcpPacket(0, 0x0A000001, 12345, 0xC0000201, 443, 110, 200, TCP_ACK | TCP_PSH, 7);
    require(smugglefintrickUpStreamPayload(t, &line, second), "second flow packet was not held");

    runTimedMessage(0);
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    require(! findPausedFixtureFlow(state)->paused, "flow remained paused after timeout");
    require(findPausedFixtureFlow(state)->confirmed, "timed-out flow was allowed to pause again");
    require(findPausedFixtureFlow(state)->queued_packets_count == 0, "timeout left queued packets behind");
    require(normal_upstream_packets == 2, "timeout did not replay every queued packet");
    require(replayed_upstream_sequences[0] == 100 && replayed_upstream_sequences[1] == 110,
            "timeout replayed queued packets out of order");

    destroyTestTunnel(t);
}

static void testQueuedPacketsRetainIndependentChecksumIntent(void)
{
    tunnel_t  normal_upstream   = {0};
    tunnel_t  normal_downstream = {0};
    tunnel_t  fin_branch        = {0};
    tunnel_t *t                 = createTestTunnel(&normal_upstream, &normal_downstream, &fin_branch);
    line_t    line;
    initializeLine(&line, 0);

    resetCounters();
    lineSetRecalculateChecksum(&line, true);
    startPausedFlow(t, &line);

    sbuf_t *unrelated = makeTcpPacket(0, 0x0A000002, 23456, 0xC0000202, 443, 300, 400, TCP_ACK | TCP_PSH, 12);
    lineSetRecalculateChecksum(&line, true);
    require(! smugglefintrickUpStreamPayload(t, &line, unrelated),
            "unrelated packet was consumed while testing checksum isolation");
    ipmanipulatorUpStreamPayload(t, &line, unrelated);
    require(! lineGetRecalculateChecksum(&line), "unrelated writer did not clear packet-line checksum scratch");

    sbuf_t *second = makeTcpPacket(0, 0x0A000001, 12345, 0xC0000201, 443, 110, 200, TCP_ACK | TCP_PSH, 7);
    require(smugglefintrickUpStreamPayload(t, &line, second), "second checksum fixture packet was not held");

    ipmanipulator_tstate_t *state = tunnelGetState(t);
    require(findPausedFixtureFlow(state)->queued_packets_count == 2, "checksum fixture queue count is wrong");
    require(findPausedFixtureFlow(state)->queued_packets[0].recalculate_checksum,
            "queued true checksum intent was lost");
    require(! findPausedFixtureFlow(state)->queued_packets[1].recalculate_checksum,
            "queued false checksum intent inherited stale state");

    runTimedMessage(0);
    require(normal_upstream_packets == 3, "checksum fixture did not emit unrelated plus queued packets");
    require(replayed_upstream_checksum_intents[1], "replayed packet lost its saved true checksum intent");
    require(! replayed_upstream_checksum_intents[2], "replayed packet inherited a stale true checksum intent");

    destroyTestTunnel(t);
}

static void testQueueCapForcesRelease(void)
{
    tunnel_t  normal_upstream   = {0};
    tunnel_t  normal_downstream = {0};
    tunnel_t  fin_branch        = {0};
    tunnel_t *t                 = createTestTunnel(&normal_upstream, &normal_downstream, &fin_branch);
    line_t    line;
    initializeLine(&line, 0);

    resetCounters();
    startPausedFlow(t, &line);

    for (uint32_t i = 0; i < 255; ++i)
    {
        sbuf_t *queued = makeTcpPacket(0, 0x0A000001, 12345, 0xC0000201, 443, 110 + i, 200, TCP_ACK | TCP_PSH, 1);
        require(smugglefintrickUpStreamPayload(t, &line, queued), "packet below queue cap was not held");
    }

    ipmanipulator_tstate_t *state = tunnelGetState(t);
    require(findPausedFixtureFlow(state)->queued_packets_capacity == kExpectedSmuggleFinQueueCapacity,
            "paused-flow queue exceeded its configured cap");

    sbuf_t *overflow = makeTcpPacket(0, 0x0A000001, 12345, 0xC0000201, 443, 500, 200, TCP_ACK | TCP_PSH, 1);
    lineSetRecalculateChecksum(&line, true);
    require(! smugglefintrickUpStreamPayload(t, &line, overflow), "queue overflow packet was not released");
    require(lineGetRecalculateChecksum(&line), "queue-cap replay erased the current packet's checksum intent");
    lineReuseBuffer(&line, overflow);
    lineSetRecalculateChecksum(&line, false);

    require(! findPausedFixtureFlow(state)->paused, "queue cap left the flow paused");
    require(findPausedFixtureFlow(state)->queued_packets_count == 0, "queue cap left packets allocated");
    require(normal_upstream_packets == 256, "queue cap did not replay every held packet");

    destroyTestTunnel(t);
}

static void testCrossWorkerEchoReleasesOwnerFlow(void)
{
    tunnel_t  normal_upstream   = {0};
    tunnel_t  normal_downstream = {0};
    tunnel_t  fin_branch        = {0};
    tunnel_t *t                 = createTestTunnel(&normal_upstream, &normal_downstream, &fin_branch);
    line_t    owner_line;
    line_t    echo_line;
    initializeLine(&owner_line, 0);
    initializeLine(&echo_line, 1);

    resetCounters();
    testWorkerBindWID(0);
    startPausedFlow(t, &owner_line);

    testWorkerBindWID(1);
    sbuf_t *echo =
        makeTcpPacket(1, 0xC0000201, 443, 0x0A000001, 12345, 200, 110, TCP_FIN | TCP_ACK | TCP_ECE | TCP_CWR, 0);
    require(smugglefintrickDownStreamPayload(t, &echo_line, echo), "ECN-marked expected echo was not consumed");

    require(timed_message_count == 2, "cross-worker echo did not schedule a release");
    require(timed_messages[1].wid == 0, "cross-worker echo release targeted the wrong worker");

    runTimedMessage(1);
    require(normal_upstream_packets == 1, "cross-worker echo did not replay the owner flow");

    runTimedMessage(0);
    require(normal_upstream_packets == 1, "stale timeout replayed the flow twice");

    destroyTestTunnel(t);
}

static void testCrossWorkerReversePacketQueuesOnOwner(void)
{
    tunnel_t  normal_upstream   = {0};
    tunnel_t  normal_downstream = {0};
    tunnel_t  fin_branch        = {0};
    tunnel_t *t                 = createTestTunnel(&normal_upstream, &normal_downstream, &fin_branch);
    line_t    owner_line;
    line_t    foreign_line;
    initializeLine(&owner_line, 0);
    initializeLine(&foreign_line, 1);

    resetCounters();
    testWorkerBindWID(0);
    startPausedFlow(t, &owner_line);

    testWorkerBindWID(1);
    sbuf_t *reverse = makeTcpPacket(1, 0xC0000201, 443, 0x0A000001, 12345, 200, 110, TCP_ACK | TCP_PSH, 8);
    lineSetRecalculateChecksum(&foreign_line, true);
    require(smugglefintrickDownStreamPayload(t, &foreign_line, reverse),
            "cross-worker reverse packet was not consumed for handoff");
    require(immediate_message_count == 1, "cross-worker reverse packet did not schedule one handoff");
    require(immediate_messages[0].wid == 0, "cross-worker reverse handoff targeted the wrong worker");
    require(! lineGetRecalculateChecksum(&foreign_line),
            "successful cross-worker handoff left checksum intent on the source line");

    ipmanipulator_tstate_t *state = tunnelGetState(t);
    require(findPausedFixtureFlow(state)->queued_packets_count == 1,
            "cross-worker reverse packet changed the owner queue before its callback");

    runImmediateMessage(0);
    require(findPausedFixtureFlow(state)->queued_packets_count == 2,
            "cross-worker reverse packet was not queued on the owner worker");
    require(findPausedFixtureFlow(state)->queued_packets[1].direction ==
                kIpManipulatorSmuggleFinQueueDirectionDownstream,
            "cross-worker reverse packet kept the wrong queue direction");
    require(findPausedFixtureFlow(state)->queued_packets[1].recalculate_checksum,
            "cross-worker reverse packet lost its checksum intent");

    runTimedMessage(0);
    require(normal_upstream_packets == 1 && downstream_after_smuggle_fin_packets == 1,
            "cross-worker flow did not replay both queued directions");
    require(downstream_entry_packets == 0, "cross-worker downstream replay restarted before smuggle-fin");
    require(replay_count == 2 && replay_directions[0] == 0 && replay_directions[1] == 1,
            "cross-worker flow replayed packets out of queue order");
    require(replay_sequences[0] == 100 && replay_sequences[1] == 200, "cross-worker flow replayed the wrong packets");
    require(replayed_downstream_checksum_intents[0], "cross-worker downstream replay lost its saved checksum request");

    destroyTestTunnel(t);
}

static void testCrossWorkerCompositionRestoresProtocolAndPortghostOnce(void)
{
    tunnel_t  normal_upstream   = {0};
    tunnel_t  normal_downstream = {0};
    tunnel_t  fin_branch        = {0};
    tunnel_t *t                 = createTestTunnel(&normal_upstream, &normal_downstream, &fin_branch);
    line_t    probe_line;
    line_t    owner_line;
    line_t    source_line;
    sbuf_t   *wire_packet = NULL;
    wid_t     owner_wid   = UINT8_MAX;
    wid_t     source_wid  = UINT8_MAX;
    uint16_t  client_port = 0;

    initializeLine(&probe_line, 0);
    resetCounters();

    ipmanipulator_tstate_t *state      = tunnelGetState(t);
    state->trick_proto_swap            = true;
    state->trick_proto_swap_tcp_number = 143;
    state->trick_proto_swap_udp_number = -1;
    state->trick_source_port_ghost     = true;
    state->trick_dest_port_ghost       = true;

    for (uint32_t port = 12000; port < 14048; ++port)
    {
        testWorkerBindWID(0);
        sbuf_t *forward =
            makeTcpPacket(0, 0x0A000001, (uint16_t) port, 0xC0000201, 443, 100, 200, TCP_ACK | TCP_PSH, 10);
        wid_t forward_wid = UINT8_MAX;
        require(deviceFlowAffineWID(sbufGetRawPtr(forward), sbufGetLength(forward), &forward_wid),
                "composition fixture could not hash the forward packet");
        lineReuseBuffer(&probe_line, forward);

        wid_t  candidate_source_wid = (wid_t) (1U - forward_wid);
        line_t candidate_source_line;
        initializeLine(&candidate_source_line, candidate_source_wid);
        testWorkerBindWID(candidate_source_wid);

        sbuf_t *candidate_wire = makeTcpPacket(
            candidate_source_wid, 0xC0000201, 443, 0x0A000001, (uint16_t) port, 200, 110, TCP_ACK | TCP_PSH, 8);
        require(portghosttrickApply(t, &candidate_source_line, &candidate_wire),
                "composition fixture could not apply portghost");
        require(candidate_wire != NULL, "composition fixture lost its wire packet");
        protoswaptrickUpStreamPayload(t, &candidate_source_line, candidate_wire);

        wid_t wire_wid = UINT8_MAX;
        require(deviceFlowAffineWID(sbufGetRawPtr(candidate_wire), sbufGetLength(candidate_wire), &wire_wid),
                "composition fixture could not hash the transformed return packet");

        if (wire_wid == candidate_source_wid && wire_wid != forward_wid)
        {
            owner_wid   = forward_wid;
            source_wid  = wire_wid;
            client_port = (uint16_t) port;
            wire_packet = candidate_wire;
            break;
        }

        lineReuseBuffer(&candidate_source_line, candidate_wire);
    }

    require(wire_packet != NULL, "composition fixture could not find a cross-worker transformed tuple");
    initializeLine(&owner_line, owner_wid);
    initializeLine(&source_line, source_wid);
    lineSetRecalculateChecksum(&source_line, true);

    testWorkerBindWID(owner_wid);
    startPausedFlowForTuple(t, &owner_line, 0x0A000001, client_port, 0xC0000201, 443);

    testWorkerBindWID(source_wid);
    require(IPH_PROTO((const struct ip_hdr *) sbufGetRawPtr(wire_packet)) != IPPROTO_TCP,
            "composition fixture did not carry a custom protocol");
    require(sbufGetLength(wire_packet) == sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) + 8U + 4U,
            "composition fixture did not carry exactly one portghost trailer");

    protoswaptrickDownStreamPayload(t, &source_line, wire_packet);
    require(portghosttrickRestore(t, &source_line, &wire_packet),
            "composition fixture could not restore the return packet");
    require(wire_packet != NULL, "composition fixture consumed a valid restored packet");
    require(IPH_PROTO((const struct ip_hdr *) sbufGetRawPtr(wire_packet)) == IPPROTO_TCP,
            "composition fixture did not restore TCP before smuggle-fin");
    require(sbufGetLength(wire_packet) == sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) + 8U,
            "composition fixture did not remove exactly one portghost trailer");

    require(smugglefintrickDownStreamPayload(t, &source_line, wire_packet),
            "composition return packet was not handed to its flow owner");
    runImmediateMessage(0);
    runTimedMessage(0);

    require(downstream_after_smuggle_fin_packets == 1 && downstream_entry_packets == 0,
            "composition return packet did not resume after smuggle-fin");
    require(replayed_downstream_protocols[0] == IPPROTO_TCP,
            "composition replay did not retain the restored TCP protocol");
    require(replayed_downstream_src_ports[0] == 443 && replayed_downstream_dst_ports[0] == client_port,
            "composition replay did not retain the original ports");
    require(replayed_downstream_packet_lengths[0] == sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) + 8U,
            "composition replay retained or removed the portghost trailer twice");
    require(replayed_downstream_checksum_intents[0],
            "composition replay did not retain its checksum-recalculation intent");

    destroyTestTunnel(t);
}

static void testStaleCrossWorkerHandoffFailsOpenAfterSmuggleFin(void)
{
    tunnel_t  normal_upstream   = {0};
    tunnel_t  normal_downstream = {0};
    tunnel_t  fin_branch        = {0};
    tunnel_t *t                 = createTestTunnel(&normal_upstream, &normal_downstream, &fin_branch);
    line_t    owner_line;
    line_t    foreign_line;
    initializeLine(&owner_line, 0);
    initializeLine(&foreign_line, 1);

    resetCounters();
    testWorkerBindWID(0);
    startPausedFlow(t, &owner_line);

    testWorkerBindWID(1);
    sbuf_t *reverse = makeTcpPacket(1, 0xC0000201, 443, 0x0A000001, 12345, 200, 110, TCP_ACK | TCP_PSH, 8);
    require(smugglefintrickDownStreamPayload(t, &foreign_line, reverse),
            "stale-handoff fixture did not schedule a reverse packet");

    runTimedMessage(0);

    ipmanipulator_tstate_t *state           = tunnelGetState(t);
    findPausedFixtureFlow(state)->confirmed = false;
    expireFinFlowNow(state, 0x0A000001, 12345, 0xC0000201, 443);
    sbuf_t *ack = makeTcpPacket(0, 0x0A000001, 12345, 0xC0000201, 443, 1, 1, TCP_ACK, 0);
    require(! smugglefintrickUpStreamPayload(t, &owner_line, ack), "stale flow cleanup packet was consumed");
    lineReuseBuffer(&owner_line, ack);
    require(findPausedFixtureFlow(state) == NULL, "stale flow entry was not reclaimed");

    startPausedFlow(t, &owner_line);
    uint32_t new_generation = findPausedFixtureFlow(state)->pause_generation;

    runImmediateMessage(0);
    require(findPausedFixtureFlow(state)->pause_generation == new_generation,
            "stale handoff changed the replacement flow generation");
    require(findPausedFixtureFlow(state)->queued_packets_count == 1,
            "stale handoff entered the replacement flow queue");
    require(downstream_after_smuggle_fin_packets == 1 && downstream_entry_packets == 0,
            "stale handoff did not fail open from the post-smuggle-fin stage");
    require(replayed_downstream_sequences[0] == 200, "stale handoff resumed the wrong packet");

    runTimedMessage(1);
    destroyTestTunnel(t);
}

static void testRejectedCrossWorkerHandoffLeavesPacketWithCaller(void)
{
    tunnel_t  normal_upstream   = {0};
    tunnel_t  normal_downstream = {0};
    tunnel_t  fin_branch        = {0};
    tunnel_t *t                 = createTestTunnel(&normal_upstream, &normal_downstream, &fin_branch);
    line_t    owner_line;
    line_t    foreign_line;
    initializeLine(&owner_line, 0);
    initializeLine(&foreign_line, 1);

    resetCounters();
    testWorkerBindWID(0);
    startPausedFlow(t, &owner_line);

    testWorkerBindWID(1);
    reject_immediate_messages = true;
    sbuf_t *reverse           = makeTcpPacket(1, 0xC0000201, 443, 0x0A000001, 12345, 200, 110, TCP_ACK | TCP_PSH, 8);
    lineSetRecalculateChecksum(&foreign_line, true);
    require(! smugglefintrickDownStreamPayload(t, &foreign_line, reverse),
            "rejected cross-worker handoff consumed the source packet");
    require(lineGetRecalculateChecksum(&foreign_line),
            "rejected cross-worker handoff cleared the source checksum intent");
    require(atomicLoadRelaxed(&owner_line.refc) == 2, "rejected cross-worker handoff leaked the owner-line lock");

    ipmanipulatorDownStreamPayloadAfterSmuggleFin(t, &foreign_line, reverse);
    require(downstream_after_smuggle_fin_packets == 1 && replayed_downstream_checksum_intents[0],
            "rejected handoff did not fall through with its checksum intent");

    runTimedMessage(0);
    require(atomicLoadRelaxed(&owner_line.refc) == 1, "rejected-handoff timeout leaked the owner-line reference");
    destroyTestTunnel(t);
}

static void testCancelledCrossWorkerHandoffReleasesOwnerReference(void)
{
    tunnel_t  normal_upstream   = {0};
    tunnel_t  normal_downstream = {0};
    tunnel_t  fin_branch        = {0};
    tunnel_t *t                 = createTestTunnel(&normal_upstream, &normal_downstream, &fin_branch);
    line_t    owner_line;
    line_t    foreign_line;
    initializeLine(&owner_line, 0);
    initializeLine(&foreign_line, 1);

    resetCounters();
    testWorkerBindWID(0);
    startPausedFlow(t, &owner_line);

    testWorkerBindWID(1);
    sbuf_t *reverse = makeTcpPacket(1, 0xC0000201, 443, 0x0A000001, 12345, 200, 110, TCP_ACK | TCP_PSH, 8);
    require(smugglefintrickDownStreamPayload(t, &foreign_line, reverse),
            "cancellation fixture did not schedule a handoff");
    require(atomicLoadRelaxed(&owner_line.refc) == 3,
            "handoff and timeout did not hold their expected owner-line references");

    cancelImmediateMessage(0);
    require(atomicLoadRelaxed(&owner_line.refc) == 2, "handoff cancellation leaked the owner-line reference");

    runTimedMessage(0);
    require(atomicLoadRelaxed(&owner_line.refc) == 1, "timeout completion leaked the owner-line reference");
    destroyTestTunnel(t);
}

static void testUnconfirmedFlowIsReclaimed(void)
{
    tunnel_t                normal_upstream   = {0};
    tunnel_t                normal_downstream = {0};
    tunnel_t                fin_branch        = {0};
    tunnel_t               *t                 = createTestTunnel(&normal_upstream, &normal_downstream, &fin_branch);
    line_t                  line;
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    initializeLine(&line, 0);

    ipmanipulator_smuggle_fin_queued_packet_t *stale_queue = memoryAllocate(sizeof(*stale_queue));
    stale_queue[0]                                         = (ipmanipulator_smuggle_fin_queued_packet_t) {
                                                .buf       = sbufCreate(64),
                                                .direction = kIpManipulatorSmuggleFinQueueDirectionUpstream,
    };
    ipmanipulator_smuggle_fin_flow_t *stale = insertFinFlow(state, 0x0A000001, 12345, 0xC0000201, 443);

    stale->queued_packets          = stale_queue;
    stale->queued_packets_count    = 1;
    stale->queued_packets_capacity = 1;

    resetCounters();
    /* Expiry is per shard, so the cleanup trigger shares the stale flow tuple. */
    sbuf_t *ack = makeTcpPacket(0, 0x0A000001, 12345, 0xC0000201, 443, 1, 1, TCP_ACK, 0);
    require(! smugglefintrickUpStreamPayload(t, &line, ack), "empty ACK unexpectedly triggered smuggle-fin");
    lineReuseBuffer(&line, ack);
    require(findPausedFixtureFlow(state) == NULL, "idle unconfirmed flow was not reclaimed");

    destroyTestTunnel(t);
}

static void testPauseGenerationSurvivesSlotReuse(void)
{
    tunnel_t                normal_upstream   = {0};
    tunnel_t                normal_downstream = {0};
    tunnel_t                fin_branch        = {0};
    tunnel_t               *t                 = createTestTunnel(&normal_upstream, &normal_downstream, &fin_branch);
    line_t                  line;
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    initializeLine(&line, 0);

    resetCounters();
    startPausedFlow(t, &line);
    uint32_t first_generation = findPausedFixtureFlow(state)->pause_generation;
    runTimedMessage(0);

    findPausedFixtureFlow(state)->confirmed = false;
    expireFinFlowNow(state, 0x0A000001, 12345, 0xC0000201, 443);
    sbuf_t *ack = makeTcpPacket(0, 0x0A000001, 12345, 0xC0000201, 443, 1, 1, TCP_ACK, 0);
    require(! smugglefintrickUpStreamPayload(t, &line, ack), "empty ACK unexpectedly triggered smuggle-fin");
    lineReuseBuffer(&line, ack);
    require(findPausedFixtureFlow(state) == NULL, "old flow entry was not reclaimed");

    resetCounters();
    startPausedFlow(t, &line);
    require(findPausedFixtureFlow(state)->pause_generation != first_generation,
            "reused flow slot repeated a live delayed-release generation");
    runTimedMessage(0);

    destroyTestTunnel(t);
}

static void testReverseOrientationReuseCancelsPausedFlow(void)
{
    tunnel_t                normal_upstream   = {0};
    tunnel_t                normal_downstream = {0};
    tunnel_t                fin_branch        = {0};
    tunnel_t               *t                 = createTestTunnel(&normal_upstream, &normal_downstream, &fin_branch);
    line_t                  line;
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    initializeLine(&line, 0);

    resetCounters();
    startPausedFlow(t, &line);

    ipmanipulator_smuggle_fin_flow_t *old_flow = findPausedFixtureFlow(state);
    require(old_flow != NULL && old_flow->paused && old_flow->queued_packets_count == 1,
            "the reverse-reuse fixture did not start with one paused original");
    uint32_t old_generation = old_flow->pause_generation;

    sbuf_t *replacement = makeTcpPacket(0, 0xC0000201, 443, 0x0A000001, 12345, 300, 400, TCP_ACK | TCP_PSH, 8);
    require(smugglefintrickUpStreamPayload(t, &line, replacement),
            "the reverse-orientation replacement payload did not start a pause");

    ipmanipulator_smuggle_fin_flow_t *new_flow = findPausedFixtureFlow(state);
    require(new_flow != NULL && new_flow->paused, "the reverse-orientation replacement flow is missing");
    require(new_flow->src_addr == lwip_htonl(0xC0000201) && new_flow->src_port == 443,
            "the sole canonical entry retained the old orientation");
    require(new_flow->pause_generation != old_generation,
            "the reverse-orientation replacement reused the old pause generation");
    require(new_flow->queued_packets_count == 1,
            "the replacement inherited or lost queued packets from the old orientation");
    require(ipmanipulatorFlowTableCount(&state->smuggle_fin_table) == 1,
            "reverse-orientation reuse created a hidden duplicate smuggle-fin entry");

    runTimedMessage(0);
    new_flow = findPausedFixtureFlow(state);
    require(new_flow != NULL && new_flow->paused && new_flow->queued_packets_count == 1,
            "the old pause timer acted on the replacement orientation");

    runTimedMessage(1);
    require(! findPausedFixtureFlow(state)->paused, "the replacement pause timer did not release its flow");
    require(normal_upstream_packets == 1, "the replacement timer did not replay exactly its own queued packet");

    destroyTestTunnel(t);
}

static void testDroppedScheduleReleasesPause(void)
{
    tunnel_t                normal_upstream   = {0};
    tunnel_t                normal_downstream = {0};
    tunnel_t                fin_branch        = {0};
    tunnel_t               *t                 = createTestTunnel(&normal_upstream, &normal_downstream, &fin_branch);
    line_t                  line;
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    initializeLine(&line, 0);

    resetCounters();
    g_schedule_should_fail = true;

    sbuf_t *packet = makeTcpPacket(0, 0x0A000001, 12345, 0xC0000201, 443, 100, 200, TCP_ACK | TCP_PSH, 10);
    require(smugglefintrickUpStreamPayload(t, &line, packet), "schedule-failure packet did not enter smuggle-fin");

    ipmanipulator_smuggle_fin_flow_t *flow = findPausedFixtureFlow(state);
    require(timed_message_count == 0, "a rejected smuggle-fin release schedule was recorded as accepted");
    require(flow != NULL && ! flow->paused && flow->queued_packets_count == 0,
            "a rejected smuggle-fin release schedule left the flow paused");
    require(normal_upstream_packets == 1, "a rejected smuggle-fin release schedule did not replay the queued packet");
    require(atomicLoadRelaxed(&line.refc) == 1, "rejected smuggle-fin release scheduling leaked a line reference");

    destroyTestTunnel(t);
}

int main(void)
{
    checkSumInit();

    test_env_t env;
    envSetup(&env);
    testUnrelatedFlowPasses();
    testPauseTimeoutReleasesFlow();
    testQueuedPacketsRetainIndependentChecksumIntent();
    testQueueCapForcesRelease();
    testCrossWorkerEchoReleasesOwnerFlow();
    testCrossWorkerReversePacketQueuesOnOwner();
    testCrossWorkerCompositionRestoresProtocolAndPortghostOnce();
    testStaleCrossWorkerHandoffFailsOpenAfterSmuggleFin();
    testRejectedCrossWorkerHandoffLeavesPacketWithCaller();
    testCancelledCrossWorkerHandoffReleasesOwnerReference();
    testUnconfirmedFlowIsReclaimed();
    testPauseGenerationSurvivesSlotReuse();
    testReverseOrientationReuseCancelsPausedFlow();
    testDroppedScheduleReleasesPause();
    envTeardown(&env);
    return 0;
}
