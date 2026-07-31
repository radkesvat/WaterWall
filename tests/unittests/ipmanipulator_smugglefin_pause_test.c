#include "IpManipulator/structure.h"
#include "tricks/smugglefin/trick.h"

#include <stdio.h>
#include <stdlib.h>

enum
{
    kMaxTimedMessages                = 16,
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

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *buffer_pools[2];
} test_env_t;

static timed_message_t timed_messages[kMaxTimedMessages];
static uint32_t        timed_message_count;
static uint32_t        normal_upstream_packets;
static uint32_t        normal_downstream_packets;
static uint32_t        mirrored_fin_packets;
static uint32_t        replayed_upstream_sequences[kExpectedSmuggleFinQueueCapacity];

void ipmanipulatorSmuggleFinTestScheduleTimed(wid_t wid, WorkerMessageCallback callback,
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

void ipmanipulatorSmuggleFinTestScheduleTimed(wid_t wid, WorkerMessageCallback callback,
                                              WorkerMessageCleanupCallback cleanup, uint32_t delay_ms, void *arg1,
                                              void *arg2, void *arg3)
{
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
}

void ipmanipulatorUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard               t;
    const uint8_t        *packet     = (const uint8_t *) sbufGetRawPtr(buf);
    const struct ip_hdr  *ipheader   = (const struct ip_hdr *) packet;
    const struct tcp_hdr *tcp_header = (const struct tcp_hdr *) (packet + IPH_HL_BYTES(ipheader));

    require(normal_upstream_packets < kExpectedSmuggleFinQueueCapacity, "upstream replay capture overflow");
    replayed_upstream_sequences[normal_upstream_packets] = lwip_ntohl(tcp_header->seqno);
    normal_upstream_packets++;
    lineReuseBuffer(l, buf);
}

void ipmanipulatorDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    normal_downstream_packets++;
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
    tl_wid                               = 0;
}

static void envTeardown(test_env_t *env)
{
    GSTATE.shortcut_buffer_pools         = NULL;
    GSTATE.masterpool_buffer_pools_large = NULL;
    GSTATE.masterpool_buffer_pools_small = NULL;
    GSTATE.workers_count                 = 0;

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
    state->smuggle_fin_flows_capacity         = kIpManipulatorSmuggleInitialFlows;
    state->smuggle_fin_flows =
        memoryAllocateZero(sizeof(*state->smuggle_fin_flows) * state->smuggle_fin_flows_capacity);
    mutexInit(&state->smuggle_fin_mutex);
    return t;
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

static void destroyTestTunnel(tunnel_t *t)
{
    cleanupTimedMessages();
    smugglefintrickDestroyState(t);
    memoryFreeAligned(t);
}

static void resetCounters(void)
{
    memoryZero(timed_messages, sizeof(timed_messages));
    timed_message_count       = 0;
    normal_upstream_packets   = 0;
    normal_downstream_packets = 0;
    mirrored_fin_packets      = 0;
    memoryZero(replayed_upstream_sequences, sizeof(replayed_upstream_sequences));
}

static void runTimedMessage(uint32_t index)
{
    require(index < timed_message_count, "timed-message index is out of range");
    timed_message_t *message = &timed_messages[index];
    require(! message->consumed, "timed message ran twice");

    tl_wid          = message->wid;
    worker_t worker = {.wid = message->wid};
    message->callback(&worker, message->arg1, message->arg2, message->arg3);
    message->consumed = true;
}

static void startPausedFlow(tunnel_t *t, line_t *line)
{
    sbuf_t *packet = makeTcpPacket(line->wid, 0x0A000001, 12345, 0xC0000201, 443, 100, 200, TCP_ACK | TCP_PSH, 10);
    require(smugglefintrickUpStreamPayload(t, line, packet), "first payload did not pause its flow");

    require(mirrored_fin_packets == 1, "mirrored FIN was not sent");
    require(timed_message_count == 1, "pause timeout was not scheduled");
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
    require(! state->smuggle_fin_flows[0].paused, "flow remained paused after timeout");
    require(state->smuggle_fin_flows[0].confirmed, "timed-out flow was allowed to pause again");
    require(state->smuggle_fin_flows[0].queued_packets_count == 0, "timeout left queued packets behind");
    require(normal_upstream_packets == 2, "timeout did not replay every queued packet");
    require(replayed_upstream_sequences[0] == 100 && replayed_upstream_sequences[1] == 110,
            "timeout replayed queued packets out of order");

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
    require(state->smuggle_fin_flows[0].queued_packets_capacity == kExpectedSmuggleFinQueueCapacity,
            "paused-flow queue exceeded its configured cap");

    sbuf_t *overflow = makeTcpPacket(0, 0x0A000001, 12345, 0xC0000201, 443, 500, 200, TCP_ACK | TCP_PSH, 1);
    require(! smugglefintrickUpStreamPayload(t, &line, overflow), "queue overflow packet was not released");
    lineReuseBuffer(&line, overflow);

    require(! state->smuggle_fin_flows[0].paused, "queue cap left the flow paused");
    require(state->smuggle_fin_flows[0].queued_packets_count == 0, "queue cap left packets allocated");
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
    tl_wid = 0;
    startPausedFlow(t, &owner_line);

    tl_wid       = 1;
    sbuf_t *echo = makeTcpPacket(1, 0xC0000201, 443, 0x0A000001, 12345, 200, 110, TCP_FIN | TCP_ACK, 0);
    require(smugglefintrickDownStreamPayload(t, &echo_line, echo), "expected echo was not consumed");

    require(timed_message_count == 2, "cross-worker echo did not schedule a release");
    require(timed_messages[1].wid == 0, "cross-worker echo release targeted the wrong worker");

    runTimedMessage(1);
    require(normal_upstream_packets == 1, "cross-worker echo did not replay the owner flow");

    runTimedMessage(0);
    require(normal_upstream_packets == 1, "stale timeout replayed the flow twice");

    destroyTestTunnel(t);
}

static void testCrossWorkerReversePacketPasses(void)
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
    tl_wid = 0;
    startPausedFlow(t, &owner_line);

    tl_wid          = 1;
    sbuf_t *reverse = makeTcpPacket(1, 0xC0000201, 443, 0x0A000001, 12345, 200, 110, TCP_ACK | TCP_PSH, 8);
    require(! smugglefintrickDownStreamPayload(t, &foreign_line, reverse),
            "cross-worker reverse packet was queued on the owner line");
    lineReuseBuffer(&foreign_line, reverse);

    ipmanipulator_tstate_t *state = tunnelGetState(t);
    require(state->smuggle_fin_flows[0].queued_packets_count == 1,
            "cross-worker reverse packet changed the owner flow queue");

    runTimedMessage(0);
    require(normal_upstream_packets == 1, "owner flow did not survive a cross-worker reverse packet");

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
    state->smuggle_fin_flows[0] = (ipmanipulator_smuggle_fin_flow_t) {
        .last_activity_ms        = 0,
        .src_addr                = lwip_htonl(0x0A000001),
        .dst_addr                = lwip_htonl(0xC0000201),
        .src_port                = 12345,
        .dst_port                = 443,
        .queued_packets          = stale_queue,
        .queued_packets_count    = 1,
        .queued_packets_capacity = 1,
        .active                  = true,
    };

    resetCounters();
    sbuf_t *ack = makeTcpPacket(0, 0x0A000002, 23456, 0xC0000202, 443, 1, 1, TCP_ACK, 0);
    require(! smugglefintrickUpStreamPayload(t, &line, ack), "empty ACK unexpectedly triggered smuggle-fin");
    lineReuseBuffer(&line, ack);
    require(! state->smuggle_fin_flows[0].active, "idle unconfirmed flow was not reclaimed");
    require(state->smuggle_fin_flows[0].queued_packets == NULL, "idle flow retained its stale queue");

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
    uint32_t first_generation = state->smuggle_fin_flows[0].pause_generation;
    runTimedMessage(0);

    state->smuggle_fin_flows[0].confirmed        = false;
    state->smuggle_fin_flows[0].last_activity_ms = 0;
    sbuf_t *ack = makeTcpPacket(0, 0x0A000002, 23456, 0xC0000202, 443, 1, 1, TCP_ACK, 0);
    require(! smugglefintrickUpStreamPayload(t, &line, ack), "empty ACK unexpectedly triggered smuggle-fin");
    lineReuseBuffer(&line, ack);
    require(! state->smuggle_fin_flows[0].active, "old flow slot was not reclaimed");

    resetCounters();
    startPausedFlow(t, &line);
    require(state->smuggle_fin_flows[0].pause_generation != first_generation,
            "reused flow slot repeated a live delayed-release generation");
    runTimedMessage(0);

    destroyTestTunnel(t);
}

int main(void)
{
    test_env_t env;
    envSetup(&env);
    testUnrelatedFlowPasses();
    testPauseTimeoutReleasesFlow();
    testQueueCapForcesRelease();
    testCrossWorkerEchoReleasesOwnerFlow();
    testCrossWorkerReversePacketPasses();
    testUnconfirmedFlowIsReclaimed();
    testPauseGenerationSurvivesSlotReuse();
    envTeardown(&env);
    return 0;
}
