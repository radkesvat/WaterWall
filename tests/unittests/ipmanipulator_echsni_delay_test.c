/*
 * ECH capture, inner-SNI matching and delayed-release lifecycle tests.
 *
 * The real shared TLS capture helper and the real bounded flow table are linked
 * in, so segmentation, ACK placement, capture limits and fail-open behaviour are
 * exercised end to end. Only the delayed-release timer is intercepted, through
 * ipmanipulatorEchSniTestScheduleTimed(), so release ordering can be asserted
 * without wall-clock waits.
 */

#include "IpManipulator/structure.h"
#include "iowatcher.h"
#include "tricks/echsnitrick/trick.h"
#include "worker_registry_fixture.h"

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

enum
{
    kMaxTimedMessages  = 64,
    kMaxForwarded      = 64,
    kShard1DelayMs     = 25,
    kShard2DelayMs     = 35,
    kClientHelloSeq    = 1001,
    kMaxPayloadRecord  = 2048,
    kFlowIdleTimeoutMs = 20U * 60U * 1000U
};

static const uint32_t kClientAddr = 0x0A000001U;
static const uint32_t kServerAddr = 0x0A000002U;
static const uint16_t kClientPort = 43123;
static const uint16_t kServerPort = 443;
static const char     kCoverSni[] = "cover.test";

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

typedef struct forwarded_packet_s
{
    uint32_t seq;
    uint16_t payload_len;
    wid_t    wid;
    uint8_t  flags;
    uint8_t  payload[kMaxPayloadRecord];
} forwarded_packet_t;

typedef struct test_env_s
{
    master_pool_t             *large_master;
    master_pool_t             *small_master;
    master_pool_t             *messages_master;
    master_pool_t             *wios_master;
    buffer_pool_t             *buffer_pools[2];
    threadsafe_generic_pool_t *wios_pools[2];
    wloop_t                   *loops[2];
    worker_t                   workers[3];
    line_t                    *lines[2];
    line_t                    *line;
} test_env_t;

typedef struct test_fixture_s
{
    tunnel_t *t;
    tunnel_t *next;
    line_t   *line;
} test_fixture_t;

static timed_message_t    timed_messages[kMaxTimedMessages];
static uint32_t           timed_message_count;
static forwarded_packet_t forwarded_packets[kMaxForwarded];
static uint32_t           forwarded_count;
static bool               g_schedule_should_fail;
static void (*forward_hook)(uint32_t index);
static test_fixture_t *forward_hook_fixture;
static test_fixture_t *before_fake_send_fixture;

static void require(bool condition, const char *message);

bool ipmanipulatorEchSniTestScheduleTimed(wid_t wid, WorkerMessageCallback callback,
                                          WorkerMessageCleanupCallback cleanup, uint32_t delay_ms, void *arg1,
                                          void *arg2, void *arg3);
void ipmanipulatorEchSniTestBeforeFakeSend(tunnel_t *t);

/* helpers.c reaches for the Smuggle-SNI owner hook; ECH tests never use it. */
void smugglesnitrickSetFlowPassthrough(tunnel_t *t, uint32_t src_addr, uint32_t dst_addr, uint16_t src_port,
                                       uint16_t dst_port)
{
    discard t;
    discard src_addr;
    discard dst_addr;
    discard src_port;
    discard dst_port;
}

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

bool ipmanipulatorEchSniTestScheduleTimed(wid_t wid, WorkerMessageCallback callback,
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

static void recordForwardedPacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;

    if (forward_hook != NULL)
    {
        forward_hook(forwarded_count);
    }

    require(forwarded_count < kMaxForwarded, "forwarded-packet capture overflow");
    require(lineGetWID(l) == getWID(), "packet emitted on a non-owner worker");

    const uint8_t        *packet      = (const uint8_t *) sbufGetRawPtr(buf);
    const struct ip_hdr  *ip          = (const struct ip_hdr *) packet;
    const struct tcp_hdr *tcp         = (const struct tcp_hdr *) (packet + IPH_HL_BYTES(ip));
    uint16_t              headers_len = (uint16_t) (IPH_HL_BYTES(ip) + TCPH_HDRLEN_BYTES(tcp));
    uint16_t              payload_len = (uint16_t) (lwip_ntohs(IPH_LEN(ip)) - headers_len);

    forwarded_packet_t *record = &forwarded_packets[forwarded_count++];

    record->seq         = lwip_ntohl(tcp->seqno);
    record->payload_len = payload_len;
    record->wid         = lineGetWID(l);
    record->flags       = TCPH_FLAGS(tcp);

    if (payload_len > 0)
    {
        memoryCopy(record->payload, packet + headers_len, min(payload_len, (uint16_t) kMaxPayloadRecord));
    }

    lineSetRecalculateChecksum(l, false);
    lineReuseBuffer(l, buf);
}

static void envSetup(test_env_t *env)
{
    memoryZero(env, sizeof(*env));
    env->large_master    = masterpoolCreateWithCapacity(128);
    env->small_master    = masterpoolCreateWithCapacity(128);
    env->messages_master = masterpoolCreateWithCapacity(128);
    env->wios_master     = masterpoolCreateWithCapacity(128);
    workerMessagesInstallMasterPoolCallbacks(env->messages_master);

    for (wid_t wid = 0; wid < 2; ++wid)
    {
        env->buffer_pools[wid] = bufferpoolCreate(env->large_master, env->small_master, 64, 8192, 4096);
        env->wios_pools[wid] =
            threadsafegenericpoolCreateWithDefaultAllocatorAndCapacity(env->wios_master, sizeof(wio_t), 64);
        env->loops[wid]         = wloopCreate(0, env->buffer_pools[wid], wid);
        env->loops[wid]->status = WLOOP_STATUS_RUNNING;
        iowatcherInit(env->loops[wid]);

        env->workers[wid].wid            = wid;
        env->workers[wid].loop           = env->loops[wid];
        env->workers[wid].buffer_pool    = env->buffer_pools[wid];
        env->workers[wid].wios_pool      = env->wios_pools[wid];
        env->workers[wid].has_event_loop = true;
        workerMessagesInit(&env->workers[wid]);

        env->lines[wid] = memoryAllocateZero(sizeof(*env->lines[wid]));
        require(env->lines[wid] != NULL, "failed to allocate a packet line");
        atomicStoreRelaxed(&env->lines[wid]->refc, 1);
        env->lines[wid]->alive = true;
        env->lines[wid]->wid   = wid;
    }
    env->workers[2].wid = 2;
    env->line           = env->lines[0];

    testWorkerRegistryInstallTable(&g_test_worker_registry, env->workers);
    GSTATE.workers_count                 = 3;
    GSTATE.shortcut_buffer_pools         = env->buffer_pools;
    GSTATE.shortcut_loops                = env->loops;
    GSTATE.shortcut_wios_pools           = env->wios_pools;
    GSTATE.masterpool_buffer_pools_large = env->large_master;
    GSTATE.masterpool_buffer_pools_small = env->small_master;
    GSTATE.masterpool_messages           = env->messages_master;
    GSTATE.mtu_size                      = 1500;
    testWorkerBindWID(0);

    /* Bounded flow tables refuse to run without a secure hash seed. */
    require(globalstateInitializeSecureRandom(), "the operating system random source is unavailable");
}

static void envTeardown(test_env_t *env)
{
    globalstateDestroySecureRandom();
    testWorkerBindWID(0);
    workerMessagesDestroy(&env->workers[0]);
    workerMessagesDestroy(&env->workers[1]);
    wloopDestroy(&env->loops[0]);
    wloopDestroy(&env->loops[1]);

    testWorkerRegistryRestore(&g_test_worker_registry);
    GSTATE.workers_count                 = 0;
    GSTATE.shortcut_buffer_pools         = NULL;
    GSTATE.shortcut_loops                = NULL;
    GSTATE.shortcut_wios_pools           = NULL;
    GSTATE.masterpool_buffer_pools_large = NULL;
    GSTATE.masterpool_buffer_pools_small = NULL;
    GSTATE.masterpool_messages           = NULL;
    GSTATE.mtu_size                      = 0;

    memoryFree(env->lines[0]);
    memoryFree(env->lines[1]);
    bufferpoolDestroy(env->buffer_pools[0]);
    bufferpoolDestroy(env->buffer_pools[1]);
    threadsafegenericpoolDestroy(env->wios_pools[0]);
    threadsafegenericpoolDestroy(env->wios_pools[1]);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolMakeEmpty(env->messages_master);
    masterpoolMakeEmpty(env->wios_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
    masterpoolDestroy(env->messages_master);
    masterpoolDestroy(env->wios_master);
}

static void resetCaptures(void)
{
    memoryZero(timed_messages, sizeof(timed_messages));
    memoryZero(forwarded_packets, sizeof(forwarded_packets));
    timed_message_count      = 0;
    forwarded_count          = 0;
    g_schedule_should_fail   = false;
    forward_hook             = NULL;
    forward_hook_fixture     = NULL;
    before_fake_send_fixture = NULL;
}

static test_fixture_t fixtureCreateWithSni(test_env_t *env, const char *configured_sni)
{
    tunnel_t *t    = memoryAllocateAlignedZero(sizeof(tunnel_t) + sizeof(ipmanipulator_tstate_t), kCpuLineCacheSize);
    tunnel_t *next = memoryAllocateAlignedZero(sizeof(tunnel_t), kCpuLineCacheSize);

    require(t != NULL && next != NULL, "failed to allocate the test tunnels");

    t->tstate_size   = sizeof(ipmanipulator_tstate_t);
    t->next          = next;
    next->fnPayloadU = recordForwardedPacket;

    ipmanipulator_tstate_t *state        = tunnelGetState(t);
    state->trick_ech_sni                 = true;
    state->trick_ech_sni_value           = stringDuplicate(configured_sni);
    state->trick_ech_sni_value_len       = (uint16_t) stringLength(configured_sni);
    state->trick_ech_sni_shard1_delay_ms = kShard1DelayMs;
    state->trick_ech_sni_shard2_delay_ms = kShard2DelayMs;
    state->trick_stateful_flow_limit     = kIpManipulatorFlowLimitMin;

    require(echsnitrickInitializeState(t), "failed to create the ech-sni-trick flow table");

    mutexInit(&state->tls_capture_mutex);
    state->tls_capture_slots_count = 16;
    state->tls_capture_slots = memoryAllocateZero(sizeof(*state->tls_capture_slots) * state->tls_capture_slots_count);
    state->tls_prestart_slots_count = 16;
    state->tls_prestart_slots =
        memoryAllocateZero(sizeof(*state->tls_prestart_slots) * state->tls_prestart_slots_count);
    require(state->tls_capture_slots != NULL && state->tls_prestart_slots != NULL,
            "failed to allocate the TLS capture slots");

    return (test_fixture_t) {.t = t, .next = next, .line = env->line};
}

static test_fixture_t fixtureCreate(test_env_t *env)
{
    return fixtureCreateWithSni(env, kCoverSni);
}

static void cleanupTimedMessages(void)
{
    for (uint32_t i = 0; i < timed_message_count; ++i)
    {
        timed_message_t *message = &timed_messages[i];
        if (! message->consumed)
        {
            testWorkerBindWID(message->wid);
            message->cleanup(message->arg1, message->arg2, message->arg3);
            message->consumed = true;
        }
    }
}

static void fixtureDestroy(test_fixture_t *fixture)
{
    cleanupTimedMessages();

    ipmanipulator_tstate_t *state = tunnelGetState(fixture->t);

    echsnitrickDestroyState(fixture->t);
    ipmanipulatorDestroyTlsCaptureState(fixture->t);
    memoryFree(state->trick_ech_sni_value);
    memoryFreeAligned(fixture->next);
    memoryFreeAligned(fixture->t);
    fixture->t    = NULL;
    fixture->next = NULL;
}

/* --------------------------------------------------------------- fixtures -- */

static void putBe16(uint8_t *dst, uint16_t value)
{
    dst[0] = (uint8_t) (value >> 8U);
    dst[1] = (uint8_t) value;
}

static void putBe24(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t) (value >> 16U);
    dst[1] = (uint8_t) (value >> 8U);
    dst[2] = (uint8_t) value;
}

typedef enum inner_kind_e
{
    kInnerKindWithSni = 0,
    kInnerKindNoSni,
    kInnerKindMalformed,
    kInnerKindTlsLookingGarbage
} inner_kind_e;

/*
 * Builds one embedded inner TLS ClientHello record. kInnerKindWithSni produces a
 * record that parseTlsRecordSni() accepts and that carries exactly `sni`.
 */
static uint16_t buildInnerClientHello(uint8_t *out, inner_kind_e kind, const char *sni)
{
    uint16_t sni_len = sni != NULL ? (uint16_t) stringLength(sni) : 0;
    uint8_t  extensions[512];
    uint16_t ext_len = 0;

    if (kind == kInnerKindTlsLookingGarbage)
    {
        /* Structurally TLS shaped, but the ClientHello vectors are nonsense. */
        uint16_t body_len  = 40;
        uint16_t total_len = (uint16_t) (9U + body_len);

        memorySet(out, 0xCC, total_len);
        out[0] = 0x16;
        out[1] = 0x03;
        out[2] = 0x03;
        putBe16(out + 3, (uint16_t) (4U + body_len));
        out[5] = 0x01;
        putBe24(out + 6, body_len);
        return total_len;
    }

    if (kind == kInnerKindWithSni)
    {
        putBe16(extensions + ext_len, 0x0000);
        putBe16(extensions + ext_len + 2, (uint16_t) (2U + 3U + sni_len));
        putBe16(extensions + ext_len + 4, (uint16_t) (3U + sni_len));
        extensions[ext_len + 6] = 0;
        putBe16(extensions + ext_len + 7, sni_len);
        memoryCopy(extensions + ext_len + 9, sni, sni_len);
        ext_len = (uint16_t) (9U + sni_len);
    }
    else
    {
        /* A padding extension keeps the record well formed but SNI-free. */
        putBe16(extensions + ext_len, 0x0015);
        putBe16(extensions + ext_len + 2, 4);
        memoryZero(extensions + ext_len + 4, 4);
        ext_len = 8;
    }

    uint16_t body_len  = (uint16_t) (43U + ext_len);
    uint16_t total_len = (uint16_t) (9U + body_len);

    memoryZero(out, total_len);
    out[0] = 0x16;
    out[1] = 0x03;
    out[2] = 0x03;
    putBe16(out + 3, (uint16_t) (4U + body_len));
    out[5] = 0x01;
    putBe24(out + 6, kind == kInnerKindMalformed ? (uint32_t) (body_len + 32U) : body_len);

    uint8_t *body = out + 9;
    body[34]      = 0;
    putBe16(body + 35, 2);
    putBe16(body + 37, 0x1301);
    body[39] = 1;
    body[40] = 0;
    putBe16(body + 41, ext_len);
    memoryCopy(body + 43, extensions, ext_len);
    return total_len;
}

typedef struct ech_fixture_options_s
{
    inner_kind_e first_kind;
    const char  *first_sni;
    inner_kind_e second_kind;
    const char  *second_sni;
    bool         has_second;
    bool         omit_ech;
    uint16_t     noise_prefix_len;
} ech_fixture_options_t;

/*
 * Builds an outer ClientHello whose GREASE encrypted_client_hello payload
 * carries the requested inner candidates.
 */
static uint16_t buildEchClientHello(uint8_t *payload, uint16_t capacity, const ech_fixture_options_t *options)
{
    uint8_t  ech_payload[1024];
    uint16_t ech_payload_len = 0;

    memorySet(ech_payload, 0x5A, options->noise_prefix_len);
    ech_payload_len = options->noise_prefix_len;

    ech_payload_len += buildInnerClientHello(ech_payload + ech_payload_len, options->first_kind, options->first_sni);

    if (options->has_second)
    {
        ech_payload_len +=
            buildInnerClientHello(ech_payload + ech_payload_len, options->second_kind, options->second_sni);
    }

    uint8_t  extensions[2048];
    uint16_t ext_len = 0;

    /* Outer server_name extension. */
    putBe16(extensions + ext_len, 0x0000);
    putBe16(extensions + ext_len + 2, 6);
    putBe16(extensions + ext_len + 4, 4);
    extensions[ext_len + 6] = 0;
    putBe16(extensions + ext_len + 7, 1);
    extensions[ext_len + 9] = 'a';
    ext_len += 10;

    if (! options->omit_ech)
    {
        uint16_t ech_ext_len = (uint16_t) (10U + ech_payload_len);

        putBe16(extensions + ext_len, 0xFE0D);
        putBe16(extensions + ext_len + 2, ech_ext_len);
        extensions[ext_len + 4] = 0;
        putBe16(extensions + ext_len + 5, 1);
        putBe16(extensions + ext_len + 7, 1);
        extensions[ext_len + 9] = 1;
        putBe16(extensions + ext_len + 10, 0);
        putBe16(extensions + ext_len + 12, ech_payload_len);
        memoryCopy(extensions + ext_len + 14, ech_payload, ech_payload_len);
        ext_len = (uint16_t) (ext_len + 4U + ech_ext_len);
    }

    uint32_t body_len  = 43U + ext_len;
    uint16_t total_len = (uint16_t) (9U + body_len);
    require(total_len <= capacity, "ECH ClientHello fixture buffer is too small");

    memoryZero(payload, total_len);
    payload[0] = 0x16;
    payload[1] = 0x03;
    payload[2] = 0x03;
    putBe16(payload + 3, (uint16_t) (4U + body_len));
    payload[5] = 0x01;
    putBe24(payload + 6, body_len);

    uint8_t *body = payload + 9;
    body[34]      = 0;
    putBe16(body + 35, 2);
    putBe16(body + 37, 0x1301);
    body[39] = 1;
    body[40] = 0;
    putBe16(body + 41, ext_len);
    memoryCopy(body + 43, extensions, ext_len);
    return total_len;
}

static uint16_t buildMatchingClientHello(uint8_t *payload, uint16_t capacity)
{
    ech_fixture_options_t options = {.first_kind = kInnerKindWithSni, .first_sni = kCoverSni};

    return buildEchClientHello(payload, capacity, &options);
}

static sbuf_t *makeTcpPacket(line_t *line, uint32_t src_addr, uint16_t src_port, uint32_t dst_addr, uint16_t dst_port,
                             uint32_t seq, uint8_t flags, const uint8_t *payload, uint16_t payload_len)
{
    uint16_t packet_len = (uint16_t) (sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) + payload_len);
    sbuf_t  *buf        = payload_len + 128U <= bufferpoolGetSmallBufferSize(lineGetBufferPool(line))
                              ? bufferpoolGetSmallBuffer(lineGetBufferPool(line))
                              : bufferpoolGetLargeBuffer(lineGetBufferPool(line));
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
    TCPH_HDRLEN_FLAGS_SET(tcp, sizeof(struct tcp_hdr) / 4U, flags);

    if (payload_len > 0)
    {
        memoryCopy(packet + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr), payload, payload_len);
    }

    return buf;
}

static sbuf_t *makeClientPacket(test_fixture_t *fixture, uint32_t seq, uint8_t flags, const uint8_t *payload,
                                uint16_t payload_len)
{
    return makeTcpPacket(
        fixture->line, kClientAddr, kClientPort, kServerAddr, kServerPort, seq, flags, payload, payload_len);
}

static sbuf_t *makeServerPacket(test_fixture_t *fixture, uint32_t seq, uint8_t flags)
{
    return makeTcpPacket(fixture->line, kServerAddr, kServerPort, kClientAddr, kClientPort, seq, flags, NULL, 0);
}

static bool feedUpstream(test_fixture_t *fixture, sbuf_t *buf)
{
    bool consumed = echsnitrickUpStreamPayload(fixture->t, fixture->line, buf);
    if (! consumed)
    {
        recordForwardedPacket(fixture->t, fixture->line, buf);
    }
    return consumed;
}

static bool feedDownstream(test_fixture_t *fixture, sbuf_t *buf)
{
    bool consumed = echsnitrickDownStreamPayload(fixture->t, fixture->line, buf);
    if (! consumed)
    {
        lineReuseBuffer(fixture->line, buf);
    }
    return consumed;
}

void ipmanipulatorEchSniTestBeforeFakeSend(tunnel_t *t)
{
    discard t;

    if (before_fake_send_fixture == NULL)
    {
        return;
    }

    test_fixture_t *fixture  = before_fake_send_fixture;
    before_fake_send_fixture = NULL;
    require(! feedDownstream(fixture, makeServerPacket(fixture, 9000, TCP_RST | TCP_ACK)),
            "downstream RST from the fake-send hook was consumed");
}

/*
 * Snapshots the ECH record for the client tuple. Production code may only use an
 * entry pointer while its shard is locked; these tests are single threaded.
 */
static bool findClientFlow(test_fixture_t *fixture, ipmanipulator_echsni_flow_t *out)
{
    ipmanipulator_tstate_t  *state = tunnelGetState(fixture->t);
    ipmanipulator_flow_key_t key =
        ipmanipulatorFlowKeyMake(lwip_htonl(kClientAddr), kClientPort, lwip_htonl(kServerAddr), kServerPort);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->echsni_table, &key);
    bool                        found = false;

    if (shard == NULL)
    {
        return false;
    }

    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->echsni_table, shard, &key);
    if (entry != NULL)
    {
        *out  = *(ipmanipulator_echsni_flow_t *) ipmanipulatorFlowEntryRecord(entry);
        found = true;
    }

    ipmanipulatorFlowShardUnlock(shard);
    return found;
}

static void replacePendingOriginalWorker(test_fixture_t *fixture, uint8_t index, line_t *foreign_line,
                                         sbuf_t *foreign_buf)
{
    ipmanipulator_tstate_t  *state = tunnelGetState(fixture->t);
    ipmanipulator_flow_key_t key =
        ipmanipulatorFlowKeyMake(lwip_htonl(kClientAddr), kClientPort, lwip_htonl(kServerAddr), kServerPort);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->echsni_table, &key);

    require(shard != NULL, "ECH foreign-owner fixture could not lock its flow shard");
    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->echsni_table, shard, &key);
    require(entry != NULL, "ECH foreign-owner fixture lost its flow");

    ipmanipulator_echsni_flow_t *flow = ipmanipulatorFlowEntryRecord(entry);
    require(flow->phase == kIpManipulatorEchSniFlowPhaseReleasing && index < flow->pending_original_count,
            "ECH foreign-owner fixture has no pending original at the requested index");
    ipmanipulator_captured_packet_t *pending = &flow->pending_original_packets[index];
    require(pending->line != NULL && pending->buf != NULL, "ECH foreign-owner fixture found an empty original");
    require(lineIsOnCurrentEventWorker(pending->line), "ECH original replacement ran off the original owner worker");

    lineReuseBuffer(pending->line, pending->buf);
    *pending = (ipmanipulator_captured_packet_t) {.line = foreign_line, .buf = foreign_buf};
    ipmanipulatorFlowShardUnlock(shard);
}

static uint32_t activeCaptureSlots(test_fixture_t *fixture)
{
    ipmanipulator_tstate_t *state  = tunnelGetState(fixture->t);
    uint32_t                active = 0;

    for (uint32_t i = 0; i < state->tls_capture_slots_count; ++i)
    {
        if (state->tls_capture_slots[i].active)
        {
            active += 1U;
        }
    }

    return active;
}

static uint8_t activeCapturePacketCount(test_fixture_t *fixture)
{
    ipmanipulator_tstate_t *state = tunnelGetState(fixture->t);

    for (uint32_t i = 0; i < state->tls_capture_slots_count; ++i)
    {
        if (state->tls_capture_slots[i].active)
        {
            return state->tls_capture_slots[i].captured_packets_count;
        }
    }

    return 0;
}

static void openFlow(test_fixture_t *fixture, uint8_t syn_flags)
{
    require(feedUpstream(fixture, makeClientPacket(fixture, kClientHelloSeq - 1U, syn_flags, NULL, 0)),
            "flow-opening SYN was not handled");
    forwarded_count = 0;
}

static void runTimedMessage(uint32_t index)
{
    require(index < timed_message_count, "timed-message index is out of range");
    timed_message_t *message = &timed_messages[index];
    require(! message->consumed, "timed message was consumed twice");
    message->consumed = true;

    testWorkerBindWID(message->wid);
    worker_t worker = {.wid = message->wid};
    message->callback(&worker, message->arg1, message->arg2, message->arg3);
}

static void cleanupTimedMessage(uint32_t index)
{
    require(index < timed_message_count, "timed-message cleanup index is out of range");
    timed_message_t *message = &timed_messages[index];
    require(! message->consumed, "timed message cleanup ran twice");
    message->consumed = true;
    testWorkerBindWID(message->wid);
    message->cleanup(message->arg1, message->arg2, message->arg3);
}

/*
 * Feeds a ClientHello split into `segments` equal-ish pieces, optionally with an
 * ACK-only packet inserted before each segment.
 */
static void feedClientHelloSegments(test_fixture_t *fixture, const uint8_t *hello, uint16_t hello_len,
                                    uint32_t segments, bool interleave_acks)
{
    uint16_t offset = 0;

    for (uint32_t i = 0; i < segments; ++i)
    {
        uint16_t remaining = (uint16_t) (hello_len - offset);
        uint16_t chunk     = i + 1U == segments ? remaining : (uint16_t) (hello_len / segments);

        require(chunk > 0, "ClientHello fixture is too small for the requested segment count");

        if (interleave_acks)
        {
            require(feedUpstream(fixture, makeClientPacket(fixture, kClientHelloSeq + offset, TCP_ACK, NULL, 0)),
                    "interleaved ACK was not handled");
        }

        require(
            feedUpstream(fixture,
                         makeClientPacket(fixture, kClientHelloSeq + offset, TCP_ACK | TCP_PSH, hello + offset, chunk)),
            "ClientHello segment was not handled");
        offset = (uint16_t) (offset + chunk);
    }

    require(offset == hello_len, "ClientHello segmentation did not cover the whole record");
}

static void feedClientHelloSplitAt(test_fixture_t *fixture, const uint8_t *hello, uint16_t hello_len,
                                   uint16_t split_offset)
{
    require(split_offset > 0 && split_offset < hello_len, "invalid ClientHello split offset");
    require(feedUpstream(fixture, makeClientPacket(fixture, kClientHelloSeq, TCP_ACK | TCP_PSH, hello, split_offset)),
            "first boundary-split ClientHello segment was not handled");
    require(feedUpstream(fixture,
                         makeClientPacket(fixture,
                                          kClientHelloSeq + split_offset,
                                          TCP_ACK | TCP_PSH,
                                          hello + split_offset,
                                          (uint16_t) (hello_len - split_offset))),
            "second boundary-split ClientHello segment was not handled");
}

/* ------------------------------------------------------------------ tests -- */

static void requireSuccessfulCapture(test_fixture_t *fixture, uint16_t hello_len, uint32_t expected_originals)
{
    require(forwarded_count == 1, "fake inner ClientHello was not emitted exactly once");
    require(forwarded_packets[0].seq > kClientHelloSeq &&
                forwarded_packets[0].seq < (uint32_t) kClientHelloSeq + hello_len,
            "fake inner packet did not use an in-stream out-of-order sequence");
    require(timed_message_count == 1, "first original release was not scheduled exactly once");
    require(timed_messages[0].delay_ms == kShard1DelayMs, "first original release used the wrong delay");

    ipmanipulator_echsni_flow_t flow = {0};
    require(findClientFlow(fixture, &flow), "successful ECH flow disappeared");
    require(flow.phase == kIpManipulatorEchSniFlowPhaseReleasing, "successful ECH flow was not finalized");
    require(flow.pending_original_count == expected_originals, "the pending batch lost or gained originals");
    require(activeCaptureSlots(fixture) == 0, "a capture slot leaked after a successful capture");
}

static void drainRelease(uint16_t hello_len, uint32_t segments)
{
    uint32_t expected = 1U + segments;

    runTimedMessage(0);

    if (segments == 1)
    {
        require(timed_message_count == 1, "a one-packet capture created a second-phase timer");
    }
    else
    {
        require(timed_message_count == 2, "the second release phase was not chained from the first");
        require(timed_messages[1].delay_ms == kShard2DelayMs, "second release phase used the wrong delay");
        runTimedMessage(1);
    }

    require(forwarded_count == expected, "the originals were not emitted exactly once each");

    uint32_t offset = 0;
    for (uint32_t i = 1; i < expected; ++i)
    {
        require(forwarded_packets[i].seq == kClientHelloSeq + offset, "an original changed its TCP sequence");
        offset += forwarded_packets[i].payload_len;
    }

    require(offset == hello_len, "the released originals did not cover the whole ClientHello");
}

static void testSegmentationMatrix(test_env_t *env)
{
    static const uint32_t segment_counts[] = {1, 2, 3, 5, 16};

    for (uint32_t i = 0; i < ARRAY_SIZE(segment_counts); ++i)
    {
        resetCaptures();

        test_fixture_t fixture = fixtureCreate(env);
        uint8_t        hello[1024];
        uint16_t       hello_len = buildMatchingClientHello(hello, sizeof(hello));

        openFlow(&fixture, TCP_SYN);
        feedClientHelloSegments(&fixture, hello, hello_len, segment_counts[i], false);

        requireSuccessfulCapture(&fixture, hello_len, segment_counts[i]);
        drainRelease(hello_len, segment_counts[i]);

        fixtureDestroy(&fixture);
    }
}

static void testBoundarySplits(test_env_t *env)
{
    uint8_t  hello[1024];
    uint16_t hello_len        = buildMatchingClientHello(hello, sizeof(hello));
    uint16_t inner_sni_offset = 0;

    for (uint16_t i = 0; i + sizeof(kCoverSni) - 1U <= hello_len; ++i)
    {
        if (memoryCompare(hello + i, kCoverSni, sizeof(kCoverSni) - 1U) == 0)
        {
            inner_sni_offset = i;
            break;
        }
    }

    require(inner_sni_offset != 0, "could not locate the inner SNI boundary fixture");

    /*
     * The fixture's outer extension vector begins at byte 52. Its ten-byte SNI
     * extension is followed by ECH, whose four-byte extension header and
     * ten-byte ECH framing precede the embedded inner ClientHello.
     */
    const uint16_t split_offsets[] = {
        2,
        7,
        53,
        70,
        (uint16_t) (inner_sni_offset + (sizeof(kCoverSni) - 1U) / 2U),
    };

    for (uint32_t i = 0; i < ARRAY_SIZE(split_offsets); ++i)
    {
        resetCaptures();

        test_fixture_t fixture = fixtureCreate(env);

        openFlow(&fixture, TCP_SYN);
        feedClientHelloSplitAt(&fixture, hello, hello_len, split_offsets[i]);
        requireSuccessfulCapture(&fixture, hello_len, 2);
        drainRelease(hello_len, 2);

        fixtureDestroy(&fixture);
    }
}

static void testExactRetransmissionDuringIncompleteCapture(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = buildMatchingClientHello(hello, sizeof(hello));
    const uint16_t first_len = 7;

    openFlow(&fixture, TCP_SYN);
    require(feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq, TCP_ACK | TCP_PSH, hello, first_len)),
            "the partial-header ClientHello segment was not held");
    require(activeCapturePacketCount(&fixture) == 1, "the first segment was not recorded once");

    require(feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq, TCP_ACK | TCP_PSH, hello, first_len)),
            "the exact capture-time retransmission was not consumed");
    require(forwarded_count == 0, "the exact capture-time retransmission disabled capture");
    require(activeCapturePacketCount(&fixture) == 1, "the exact retransmission became a second original");

    require(feedUpstream(&fixture,
                         makeClientPacket(&fixture,
                                          kClientHelloSeq + first_len,
                                          TCP_ACK | TCP_PSH,
                                          hello + first_len,
                                          (uint16_t) (hello_len - first_len))),
            "capture did not continue after an exact retransmission");

    requireSuccessfulCapture(&fixture, hello_len, 2);
    drainRelease(hello_len, 2);
    fixtureDestroy(&fixture);
}

static void testAckOnlyPacketsDoNotDisableCapture(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = buildMatchingClientHello(hello, sizeof(hello));

    openFlow(&fixture, TCP_SYN);

    /* ACK-only traffic before the first ClientHello segment must pass unchanged. */
    require(feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq, TCP_ACK, NULL, 0)),
            "leading ACK was not handled");
    require(forwarded_count == 1 && forwarded_packets[0].payload_len == 0, "leading ACK was not forwarded unchanged");

    ipmanipulator_echsni_flow_t flow = {0};
    require(findClientFlow(&fixture, &flow), "the ECH flow disappeared after a leading ACK");
    require(flow.phase == kIpManipulatorEchSniFlowPhaseAwaitingClientHello,
            "a leading ACK moved the flow out of capture eligibility");

    forwarded_count = 0;
    feedClientHelloSegments(&fixture, hello, hello_len, 3, true);

    /* Three interleaved ACK-only packets pass through plus the fake inner packet. */
    require(forwarded_count == 4, "the interleaved ACKs and the fake inner packet were not all emitted");
    require(findClientFlow(&fixture, &flow), "the ECH flow disappeared after an interleaved capture");
    require(flow.phase == kIpManipulatorEchSniFlowPhaseReleasing,
            "interleaved ACK-only packets prevented a successful capture");

    fixtureDestroy(&fixture);
}

static void testSeventeenthSegmentFailsOpen(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = buildMatchingClientHello(hello, sizeof(hello));

    openFlow(&fixture, TCP_SYN);

    /*
     * The first segment must be long enough to be recognized as a ClientHello
     * record start; the rest are single bytes so exactly seventeen packets are
     * required to complete the record.
     */
    uint16_t first_len = (uint16_t) (hello_len - 16U);
    uint16_t offsets[17];

    offsets[0] = 0;
    require(feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq, TCP_ACK | TCP_PSH, hello, first_len)),
            "the first capture segment was not handled");

    uint16_t offset = first_len;
    for (uint32_t i = 1; i < 16U; ++i)
    {
        offsets[i] = offset;
        require(
            feedUpstream(&fixture,
                         makeClientPacket(&fixture, kClientHelloSeq + offset, TCP_ACK | TCP_PSH, hello + offset, 1)),
            "a capture segment was not handled");
        offset += 1U;
    }

    require(forwarded_count == 0, "a pending capture emitted a packet early");

    /* The seventeenth required packet exceeds the shared capture bound. */
    offsets[16] = offset;
    require(feedUpstream(&fixture,
                         makeClientPacket(&fixture,
                                          kClientHelloSeq + offset,
                                          TCP_ACK | TCP_PSH,
                                          hello + offset,
                                          (uint16_t) (hello_len - offset))),
            "the seventeenth segment was not handled");

    require(forwarded_count == 17, "the capture limit did not release every held packet plus the current one");
    for (uint32_t i = 0; i < 17U; ++i)
    {
        require(forwarded_packets[i].seq == (uint32_t) kClientHelloSeq + offsets[i],
                "a released packet changed its sequence or order");
    }

    ipmanipulator_echsni_flow_t flow = {0};
    require(findClientFlow(&fixture, &flow), "the ECH flow disappeared after the capture limit");
    require(flow.phase == kIpManipulatorEchSniFlowPhasePassthrough, "the capture limit did not fail open");
    require(activeCaptureSlots(&fixture) == 0, "the capture limit leaked a slot");
    require(timed_message_count == 0, "the capture limit scheduled a delayed release");

    fixtureDestroy(&fixture);
}

static void testSequenceGapFailsOpen(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = buildMatchingClientHello(hello, sizeof(hello));

    openFlow(&fixture, TCP_SYN);

    require(feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq, TCP_ACK | TCP_PSH, hello, 40)),
            "first ClientHello segment was not held");
    require(forwarded_count == 0, "the held segment was emitted early");

    /* A gap the helper cannot bridge must release the held bytes first, in order. */
    require(
        feedUpstream(&fixture,
                     makeClientPacket(
                         &fixture, kClientHelloSeq + 60U, TCP_ACK | TCP_PSH, hello + 60, (uint16_t) (hello_len - 60U))),
        "the out-of-sequence segment was not handled");

    require(forwarded_count == 2, "the gap did not release the held packet and the current one");
    require(forwarded_packets[0].seq == kClientHelloSeq, "the held packet was not released first");
    require(forwarded_packets[1].seq == kClientHelloSeq + 60U, "the current packet was released out of order");

    ipmanipulator_echsni_flow_t flow = {0};
    require(findClientFlow(&fixture, &flow), "the ECH flow disappeared after a sequence gap");
    require(flow.phase == kIpManipulatorEchSniFlowPhasePassthrough, "a sequence gap did not fail open");
    require(activeCaptureSlots(&fixture) == 0, "a sequence gap leaked a capture slot");

    fixtureDestroy(&fixture);
}

static void testCaptureOutOfOrderAndPartialOverlapFailOpen(test_env_t *env)
{
    static const struct
    {
        const char *name;
        uint16_t    second_offset;
        uint16_t    second_len;
    } cases[] = {
        {"out-of-order segment", 80, 24},
        {"partial overlap", 20, 40},
    };

    for (uint32_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        resetCaptures();

        test_fixture_t fixture = fixtureCreate(env);
        uint8_t        hello[1024];
        uint16_t       hello_len = buildMatchingClientHello(hello, sizeof(hello));

        require(cases[i].second_offset + cases[i].second_len <= hello_len, cases[i].name);
        openFlow(&fixture, TCP_SYN);
        require(feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq, TCP_ACK | TCP_PSH, hello, 40)),
                "the first sequence-failure segment was not held");
        require(feedUpstream(&fixture,
                             makeClientPacket(&fixture,
                                              kClientHelloSeq + cases[i].second_offset,
                                              TCP_ACK | TCP_PSH,
                                              hello + cases[i].second_offset,
                                              cases[i].second_len)),
                cases[i].name);

        require(forwarded_count == 2, "a sequence failure did not release the held and current packets");
        require(forwarded_packets[0].seq == kClientHelloSeq, "a sequence failure reordered the held original");
        require(forwarded_packets[1].seq == (uint32_t) kClientHelloSeq + cases[i].second_offset,
                "a sequence failure changed the current packet sequence");

        ipmanipulator_echsni_flow_t flow = {0};
        require(findClientFlow(&fixture, &flow), "a sequence failure removed the ECH flow");
        require(flow.phase == kIpManipulatorEchSniFlowPhasePassthrough,
                "a sequence failure did not mark the generation passthrough");
        require(activeCaptureSlots(&fixture) == 0, "a sequence failure leaked a capture slot");

        fixtureDestroy(&fixture);
    }
}

static void testSynClassification(test_env_t *env)
{
    static const struct
    {
        const char *name;
        uint8_t     flags;
        uint16_t    payload_len;
        bool        creates_flow;
    } cases[] = {
        {"plain SYN", TCP_SYN, 0, true},
        {"ECN SYN", TCP_SYN | TCP_ECE | TCP_CWR, 0, true},
        {"SYN|ACK", TCP_SYN | TCP_ACK, 0, false},
        {"SYN|FIN", TCP_SYN | TCP_FIN, 0, false},
        {"SYN|RST", TCP_SYN | TCP_RST, 0, false},
        {"payload-bearing SYN", TCP_SYN, 8, false},
    };

    for (uint32_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        resetCaptures();

        test_fixture_t fixture = fixtureCreate(env);
        uint8_t        payload[8];

        memorySet(payload, 0x33, sizeof(payload));

        discard feedUpstream(&fixture,
                             makeClientPacket(&fixture,
                                              kClientHelloSeq - 1U,
                                              cases[i].flags,
                                              cases[i].payload_len > 0 ? payload : NULL,
                                              cases[i].payload_len));

        ipmanipulator_echsni_flow_t flow  = {0};
        bool                        found = findClientFlow(&fixture, &flow);

        require(found == cases[i].creates_flow, cases[i].name);
        if (found)
        {
            require(flow.generation != 0, "a created generation is zero");
            require(flow.phase == kIpManipulatorEchSniFlowPhaseAwaitingClientHello,
                    "a fresh generation did not start awaiting a ClientHello");
        }

        fixtureDestroy(&fixture);
    }
}

static void testInnerSniMatchingMatrix(test_env_t *env)
{
    static char long_sni[kIpManipulatorMaxTlsHostNameLen + 1];

    memorySet(long_sni, 'b', kIpManipulatorMaxTlsHostNameLen);
    long_sni[kIpManipulatorMaxTlsHostNameLen] = '\0';

    const struct
    {
        const char           *name;
        const char           *configured;
        ech_fixture_options_t options;
        bool                  expect_success;
    } cases[] = {
        {"correct configured inner SNI", kCoverSni, {.first_kind = kInnerKindWithSni, .first_sni = kCoverSni}, true},
        {"wrong inner SNI", kCoverSni, {.first_kind = kInnerKindWithSni, .first_sni = "other.test"}, false},
        {"missing inner SNI", kCoverSni, {.first_kind = kInnerKindNoSni}, false},
        {"malformed inner ClientHello", kCoverSni, {.first_kind = kInnerKindMalformed, .first_sni = kCoverSni}, false},
        {"TLS-looking bytes that are not a ClientHello", kCoverSni, {.first_kind = kInnerKindTlsLookingGarbage}, false},
        {"one wrong candidate followed by one exact candidate",
         kCoverSni,
         {.first_kind  = kInnerKindWithSni,
          .first_sni   = "other.test",
          .second_kind = kInnerKindWithSni,
          .second_sni  = kCoverSni,
          .has_second  = true},
         true},
        {"two exact matching candidates",
         kCoverSni,
         {.first_kind  = kInnerKindWithSni,
          .first_sni   = kCoverSni,
          .second_kind = kInnerKindWithSni,
          .second_sni  = kCoverSni,
          .has_second  = true},
         false},
        {"no encrypted_client_hello extension",
         kCoverSni,
         {.first_kind = kInnerKindWithSni, .first_sni = kCoverSni, .omit_ech = true},
         false},
        {"configured value at the 255-byte boundary",
         long_sni,
         {.first_kind = kInnerKindWithSni, .first_sni = long_sni},
         true},
    };

    for (uint32_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        resetCaptures();

        test_fixture_t fixture = fixtureCreateWithSni(env, cases[i].configured);
        uint8_t        hello[2048];
        uint16_t       hello_len = buildEchClientHello(hello, sizeof(hello), &cases[i].options);

        openFlow(&fixture, TCP_SYN);
        require(
            feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq, TCP_ACK | TCP_PSH, hello, hello_len)),
            "the one-packet ClientHello was not handled");

        if (cases[i].expect_success)
        {
            require(forwarded_count == 1, cases[i].name);
            require(timed_message_count == 1, "a successful match did not schedule the first release");
        }
        else
        {
            require(forwarded_count == 1, "a rejected fixture did not release its original exactly once");
            require(forwarded_packets[0].seq == kClientHelloSeq && forwarded_packets[0].payload_len == hello_len,
                    "a rejected fixture changed the original packet");
            require(memoryCompare(forwarded_packets[0].payload, hello, hello_len) == 0,
                    "a rejected fixture changed the original payload bytes");
            require(timed_message_count == 0, cases[i].name);

            ipmanipulator_echsni_flow_t flow = {0};
            require(findClientFlow(&fixture, &flow), "a rejected fixture removed its flow");
            require(flow.phase == kIpManipulatorEchSniFlowPhasePassthrough, "a rejected fixture did not fail open");
        }

        require(activeCaptureSlots(&fixture) == 0, "a capture slot leaked");
        fixtureDestroy(&fixture);
    }
}

static void startSuccessfulDelay(test_fixture_t *fixture, uint8_t *hello, uint16_t *hello_len)
{
    *hello_len = buildMatchingClientHello(hello, 1024);

    openFlow(fixture, TCP_SYN);
    feedClientHelloSegments(fixture, hello, *hello_len, 2, false);
    requireSuccessfulCapture(fixture, *hello_len, 2);
}

static void testForeignWorkerReleaseDrainForwardsOnOwner(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = 0;

    startSuccessfulDelay(&fixture, hello, &hello_len);
    uint16_t first_len = (uint16_t) (hello_len / 2U);

    testWorkerBindWID(1);
    sbuf_t *foreign_first = makeTcpPacket(env->lines[1],
                                          kClientAddr,
                                          kClientPort,
                                          kServerAddr,
                                          kServerPort,
                                          kClientHelloSeq,
                                          TCP_ACK | TCP_PSH,
                                          hello,
                                          first_len);
    testWorkerBindWID(0);
    replacePendingOriginalWorker(&fixture, 0, env->lines[1], foreign_first);

    runTimedMessage(0);
    require(forwarded_count == 1, "foreign ECH original was emitted inline on the release worker");

    testWorkerBindWID(1);
    wloopProcessEvents(env->loops[1], 0);
    require(forwarded_count == 2 && forwarded_packets[1].wid == 1 && forwarded_packets[1].seq == kClientHelloSeq &&
                forwarded_packets[1].payload_len == first_len,
            "foreign ECH original was not replayed on its owner worker");
    require(memoryCompare(forwarded_packets[1].payload, hello, first_len) == 0,
            "foreign ECH original changed during owner-worker replay");

    runTimedMessage(1);
    require(forwarded_count == 3 && forwarded_packets[2].wid == 0 &&
                forwarded_packets[2].seq == (uint32_t) kClientHelloSeq + first_len,
            "owner ECH original did not remain on the release worker");

    testWorkerBindWID(0);
    fixtureDestroy(&fixture);
}

static void testGracefulCloseDrainsForeignOriginalOnOwner(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = 0;

    startSuccessfulDelay(&fixture, hello, &hello_len);
    uint16_t first_len = (uint16_t) (hello_len / 2U);

    testWorkerBindWID(1);
    sbuf_t *foreign_first = makeTcpPacket(env->lines[1],
                                          kClientAddr,
                                          kClientPort,
                                          kServerAddr,
                                          kServerPort,
                                          kClientHelloSeq,
                                          TCP_ACK | TCP_PSH,
                                          hello,
                                          first_len);
    testWorkerBindWID(0);
    replacePendingOriginalWorker(&fixture, 0, env->lines[1], foreign_first);

    require(
        ! feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq + hello_len, TCP_FIN | TCP_ACK, NULL, 0)),
        "graceful close with a foreign ECH original was swallowed");
    require(forwarded_count == 3 && forwarded_packets[1].wid == 0 &&
                forwarded_packets[1].seq == (uint32_t) kClientHelloSeq + first_len &&
                (forwarded_packets[2].flags & TCP_FIN) != 0,
            "graceful close did not emit owner-local bytes before FIN");

    testWorkerBindWID(1);
    wloopProcessEvents(env->loops[1], 0);
    require(forwarded_count == 4 && forwarded_packets[3].wid == 1 && forwarded_packets[3].seq == kClientHelloSeq &&
                forwarded_packets[3].payload_len == first_len,
            "graceful close did not replay the foreign original on its owner worker");
    require(memoryCompare(forwarded_packets[3].payload, hello, first_len) == 0,
            "graceful-close replay changed the foreign ECH original");

    ipmanipulator_echsni_flow_t flow = {0};
    require(! findClientFlow(&fixture, &flow), "graceful close left its ECH flow alive");
    runTimedMessage(0);
    require(forwarded_count == 4, "stale ECH timer replayed a foreign original twice");

    testWorkerBindWID(0);
    fixtureDestroy(&fixture);
}

static void closeDuringFirstSecondPhaseEmission(uint32_t index)
{
    if (index != 2U)
    {
        return;
    }

    forward_hook = NULL;
    require(forward_hook_fixture != NULL, "the phase-two close hook has no fixture");
    require(! feedDownstream(forward_hook_fixture, makeServerPacket(forward_hook_fixture, 9000, TCP_RST | TCP_ACK)),
            "downstream RST from the phase-two hook was consumed");
}

static void testDownstreamRstDuringSecondPhaseEmission(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = buildMatchingClientHello(hello, sizeof(hello));

    openFlow(&fixture, TCP_SYN);
    feedClientHelloSegments(&fixture, hello, hello_len, 4, false);
    requireSuccessfulCapture(&fixture, hello_len, 4);

    runTimedMessage(0);
    require(forwarded_count == 2, "the first original did not emit before the phase-two close hook");

    forward_hook_fixture = &fixture;
    forward_hook         = closeDuringFirstSecondPhaseEmission;
    runTimedMessage(1);
    forward_hook_fixture = NULL;
    forward_hook         = NULL;

    require(forwarded_count == 3, "a phase-two close did not cancel the later pending originals");

    fixtureDestroy(&fixture);
}

static void killLineDuringFirstSecondPhaseEmission(uint32_t index)
{
    if (index != 2U)
    {
        return;
    }

    forward_hook = NULL;
    require(forward_hook_fixture != NULL, "the phase-two line-death hook has no fixture");
    forward_hook_fixture->line->alive = false;
}

static void testDeadLineDuringSecondPhaseDrains(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = buildMatchingClientHello(hello, sizeof(hello));

    openFlow(&fixture, TCP_SYN);
    feedClientHelloSegments(&fixture, hello, hello_len, 4, false);
    requireSuccessfulCapture(&fixture, hello_len, 4);
    runTimedMessage(0);

    forward_hook_fixture = &fixture;
    forward_hook         = killLineDuringFirstSecondPhaseEmission;
    runTimedMessage(1);
    forward_hook_fixture = NULL;
    forward_hook         = NULL;

    ipmanipulator_echsni_flow_t flow = {0};
    require(findClientFlow(&fixture, &flow), "line death removed the releasing ECH flow");
    require(flow.phase == kIpManipulatorEchSniFlowPhasePassthrough,
            "line death stranded the ECH flow in its releasing phase");
    for (uint8_t i = 0; i < flow.pending_original_count; ++i)
    {
        require(flow.pending_original_packets[i].buf == NULL, "line death left a pending original undrained");
    }

    fixture.line->alive = true;
    fixtureDestroy(&fixture);
}

static void testCloseDuringFakeInnerEmission(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = buildMatchingClientHello(hello, sizeof(hello));

    openFlow(&fixture, TCP_SYN);
    before_fake_send_fixture = &fixture;
    feedClientHelloSegments(&fixture, hello, hello_len, 2, false);
    before_fake_send_fixture = NULL;

    require(forwarded_count == 0, "the fake inner packet emitted after its generation closed");
    require(timed_message_count == 0, "the closed generation scheduled an original-release timer");
    require(activeCaptureSlots(&fixture) == 0, "the fake-send close leaked a capture slot");

    ipmanipulator_echsni_flow_t flow = {0};
    require(! findClientFlow(&fixture, &flow), "the fake-send close left its flow record alive");

    fixtureDestroy(&fixture);
}

static void testDownstreamRstBeforeFirstRelease(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = 0;

    startSuccessfulDelay(&fixture, hello, &hello_len);
    discard hello_len;

    require(! feedDownstream(&fixture, makeServerPacket(&fixture, 9000, TCP_RST | TCP_ACK)),
            "downstream RST was consumed");

    ipmanipulator_echsni_flow_t flow = {0};
    require(! findClientFlow(&fixture, &flow), "downstream RST did not remove the ECH flow");

    runTimedMessage(0);
    require(forwarded_count == 1, "a stale first-phase timer emitted after a downstream RST");

    fixtureDestroy(&fixture);
}

static void testDownstreamFinBetweenReleases(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = 0;

    startSuccessfulDelay(&fixture, hello, &hello_len);
    discard hello_len;

    runTimedMessage(0);
    require(forwarded_count == 2, "the first original did not emit before the downstream FIN");

    require(! feedDownstream(&fixture, makeServerPacket(&fixture, 9000, TCP_FIN | TCP_ACK)),
            "downstream FIN was consumed");

    ipmanipulator_echsni_flow_t flow = {0};
    require(! findClientFlow(&fixture, &flow), "downstream FIN did not remove the ECH flow");

    runTimedMessage(1);
    require(forwarded_count == 2, "the second release phase emitted after a downstream FIN");

    fixtureDestroy(&fixture);
}

static void testGracefulFinFlushesPendingOriginals(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = 0;

    startSuccessfulDelay(&fixture, hello, &hello_len);
    require(
        ! feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq + hello_len, TCP_FIN | TCP_ACK, NULL, 0)),
        "upstream FIN was swallowed during release");

    uint16_t first_len = (uint16_t) (hello_len / 2U);
    require(forwarded_count == 4, "graceful FIN did not flush both originals before itself");
    require(forwarded_packets[1].seq == kClientHelloSeq && forwarded_packets[1].payload_len == first_len,
            "graceful FIN did not flush the first original first");
    require(forwarded_packets[2].seq == (uint32_t) kClientHelloSeq + first_len &&
                forwarded_packets[2].payload_len == hello_len - first_len,
            "graceful FIN did not flush the second original second");
    require((forwarded_packets[3].flags & TCP_FIN) != 0, "graceful FIN was not forwarded after the originals");

    ipmanipulator_echsni_flow_t flow = {0};
    require(! findClientFlow(&fixture, &flow), "upstream FIN did not remove the ECH flow");

    runTimedMessage(0);
    require(forwarded_count == 4, "a stale timer emitted after an upstream FIN");

    fixtureDestroy(&fixture);
}

static void testGracefulFinAfterPartialReleaseFlushesRemainder(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = 0;

    startSuccessfulDelay(&fixture, hello, &hello_len);
    runTimedMessage(0);
    require(forwarded_count == 2, "the first original did not emit before the partial-release FIN");

    require(
        ! feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq + hello_len, TCP_FIN | TCP_ACK, NULL, 0)),
        "upstream FIN was swallowed after the first release");

    uint16_t first_len = (uint16_t) (hello_len / 2U);
    require(forwarded_count == 4, "partial-release FIN did not flush the remaining original before itself");
    require(forwarded_packets[2].seq == (uint32_t) kClientHelloSeq + first_len &&
                forwarded_packets[2].payload_len == hello_len - first_len,
            "partial-release FIN duplicated the first original or skipped the second");
    require((forwarded_packets[3].flags & TCP_FIN) != 0,
            "partial-release FIN was not forwarded after the remaining original");

    runTimedMessage(1);
    require(forwarded_count == 4, "a stale second-phase timer emitted after an upstream FIN");

    fixtureDestroy(&fixture);
}

static void testRstStillDiscardsPendingOriginals(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = 0;

    startSuccessfulDelay(&fixture, hello, &hello_len);
    discard hello_len;

    require(! feedUpstream(&fixture, makeClientPacket(&fixture, 9000, TCP_RST | TCP_ACK, NULL, 0)),
            "upstream RST was swallowed during release");
    require(forwarded_count == 2 && (forwarded_packets[1].flags & TCP_RST) != 0,
            "upstream RST did not discard pending originals");

    ipmanipulator_echsni_flow_t flow = {0};
    require(! findClientFlow(&fixture, &flow), "upstream RST did not remove the ECH flow");

    runTimedMessage(0);
    require(forwarded_count == 2, "a stale timer emitted after an upstream RST");

    fixtureDestroy(&fixture);
}

static void testUpstreamFinFlushesIncompleteCapture(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = buildMatchingClientHello(hello, sizeof(hello));

    discard hello_len;

    openFlow(&fixture, TCP_SYN);
    require(feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq, TCP_ACK | TCP_PSH, hello, 40)),
            "the first ClientHello segment was not held");
    require(forwarded_count == 0, "the held segment was emitted early");

    require(! feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq + 40U, TCP_FIN | TCP_ACK, NULL, 0)),
            "upstream FIN was consumed during an incomplete capture");

    require(forwarded_count == 2, "the FIN path did not release the held original and then the FIN");
    require(forwarded_packets[0].seq == kClientHelloSeq && forwarded_packets[0].payload_len == 40,
            "the held original was not released first");
    require((forwarded_packets[1].flags & TCP_FIN) != 0, "the close packet was not forwarded after the original");

    ipmanipulator_echsni_flow_t flow = {0};
    require(! findClientFlow(&fixture, &flow), "upstream FIN left the ECH flow in the table");
    require(activeCaptureSlots(&fixture) == 0, "upstream FIN leaked a capture slot");

    fixtureDestroy(&fixture);
}

static void testDownstreamRstCancelsIncompleteCapture(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = buildMatchingClientHello(hello, sizeof(hello));

    discard hello_len;

    openFlow(&fixture, TCP_SYN);
    require(feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq, TCP_ACK | TCP_PSH, hello, 40)),
            "the first ClientHello segment was not held");

    require(! feedDownstream(&fixture, makeServerPacket(&fixture, 9000, TCP_RST | TCP_ACK)),
            "downstream RST was consumed");

    require(forwarded_count == 0, "downstream RST injected the cancelled capture upstream");

    ipmanipulator_echsni_flow_t flow = {0};
    require(! findClientFlow(&fixture, &flow), "downstream RST left the ECH flow in the table");
    require(activeCaptureSlots(&fixture) == 0, "downstream RST leaked a capture slot");

    fixtureDestroy(&fixture);
}

static void testTupleReuseInvalidatesOldGeneration(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = 0;

    startSuccessfulDelay(&fixture, hello, &hello_len);
    discard hello_len;

    ipmanipulator_echsni_flow_t before = {0};
    require(findClientFlow(&fixture, &before), "the successful flow disappeared");

    require(feedUpstream(&fixture,
                         makeTcpPacket(
                             fixture.line, kServerAddr, kServerPort, kClientAddr, kClientPort, 7000, TCP_SYN, NULL, 0)),
            "the reverse-orientation reused-tuple SYN was not handled");

    ipmanipulator_echsni_flow_t replacement = {0};
    require(findClientFlow(&fixture, &replacement), "the reused tuple did not create a replacement generation");
    require(replacement.generation != 0 && replacement.generation != before.generation,
            "the reused tuple retained the old generation");
    require(replacement.phase == kIpManipulatorEchSniFlowPhaseAwaitingClientHello,
            "stale flow state leaked into the replacement generation");
    require(replacement.pending_original_count == 0, "the replacement generation inherited pending originals");
    require(replacement.src_addr == lwip_htonl(kServerAddr) && replacement.src_port == kServerPort,
            "the canonical entry retained the old tuple orientation");

    ipmanipulator_tstate_t *state = tunnelGetState(fixture.t);
    require(ipmanipulatorFlowTableCount(&state->echsni_table) == 1,
            "reverse-orientation reuse created a duplicate canonical flow entry");

    uint32_t forwarded_before_timer = forwarded_count;
    runTimedMessage(0);
    require(forwarded_count == forwarded_before_timer, "an old-generation timer emitted into a reused tuple");

    fixtureDestroy(&fixture);
}

static void testTupleReuseCancelsIncompleteCapture(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = buildMatchingClientHello(hello, sizeof(hello));

    discard hello_len;

    openFlow(&fixture, TCP_SYN);
    require(feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq, TCP_ACK | TCP_PSH, hello, 40)),
            "the first ClientHello segment was not held");
    require(activeCaptureSlots(&fixture) == 1, "the capture slot was not created");

    ipmanipulator_tstate_t *state           = tunnelGetState(fixture.t);
    uint32_t                slot_index      = UINT32_MAX;
    uint32_t                slot_generation = 0;

    for (uint32_t i = 0; i < state->tls_capture_slots_count; ++i)
    {
        if (state->tls_capture_slots[i].active)
        {
            slot_index      = i;
            slot_generation = state->tls_capture_slots[i].generation;
            break;
        }
    }

    require(slot_index != UINT32_MAX, "the old capture slot could not be identified");

    require(feedUpstream(&fixture,
                         makeTcpPacket(
                             fixture.line, kServerAddr, kServerPort, kClientAddr, kClientPort, 7000, TCP_SYN, NULL, 0)),
            "the reverse-orientation reused-tuple SYN was not handled");

    require(activeCaptureSlots(&fixture) == 0, "the reused tuple left the old capture slot active");

    ipmanipulator_echsni_flow_t flow = {0};
    require(findClientFlow(&fixture, &flow), "the replacement generation is missing");
    require(flow.phase == kIpManipulatorEchSniFlowPhaseAwaitingClientHello,
            "the replacement generation did not start fresh");
    require(flow.src_addr == lwip_htonl(kServerAddr) && flow.src_port == kServerPort,
            "the incomplete-capture replacement retained the old orientation");
    require(ipmanipulatorFlowTableCount(&state->echsni_table) == 1,
            "incomplete-capture tuple reuse created a duplicate canonical entry");

    uint32_t                                 forwarded_before_stale_timeout = forwarded_count;
    ipmanipulator_tls_capture_timeout_msg_t *msg                            = memoryAllocate(sizeof(*msg));
    *msg = (ipmanipulator_tls_capture_timeout_msg_t) {
        .slot_index = slot_index,
        .generation = slot_generation,
    };
    ipmanipulatorReleasePendingCaptureOnWorker(NULL, fixture.t, msg, NULL);

    require(forwarded_count == forwarded_before_stale_timeout,
            "a real stale capture-timeout callback emitted an old original");
    require(findClientFlow(&fixture, &flow) && flow.phase == kIpManipulatorEchSniFlowPhaseAwaitingClientHello,
            "a real stale capture-timeout callback changed the replacement generation");

    fixtureDestroy(&fixture);
}

static void testCaptureTimeoutReleasesAndFailsOpen(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = buildMatchingClientHello(hello, sizeof(hello));

    discard hello_len;

    openFlow(&fixture, TCP_SYN);
    require(feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq, TCP_ACK | TCP_PSH, hello, 40)),
            "the first ClientHello segment was not held");

    ipmanipulator_tstate_t *state      = tunnelGetState(fixture.t);
    uint32_t                slot_index = UINT32_MAX;

    for (uint32_t i = 0; i < state->tls_capture_slots_count; ++i)
    {
        if (state->tls_capture_slots[i].active)
        {
            slot_index = i;
            break;
        }
    }

    require(slot_index != UINT32_MAX, "no capture slot became active");

    ipmanipulator_tls_capture_timeout_msg_t *msg = memoryAllocate(sizeof(*msg));
    *msg                                         = (ipmanipulator_tls_capture_timeout_msg_t) {.slot_index = slot_index,
                                                                                              .generation = state->tls_capture_slots[slot_index].generation};
    state->tls_capture_slots[slot_index].last_update_ms = 0;

    ipmanipulatorReleasePendingCaptureOnWorker(NULL, fixture.t, msg, NULL);

    require(forwarded_count == 1, "the capture timeout did not release the held original exactly once");
    require(forwarded_packets[0].seq == kClientHelloSeq && forwarded_packets[0].payload_len == 40,
            "the capture timeout changed the released original");

    ipmanipulator_echsni_flow_t flow = {0};
    require(findClientFlow(&fixture, &flow), "the capture timeout removed the ECH flow");
    require(flow.phase == kIpManipulatorEchSniFlowPhasePassthrough, "the capture timeout did not fail open");
    require(activeCaptureSlots(&fixture) == 0, "the capture timeout leaked a slot");

    /* A stale timeout for a generation that no longer exists is a no-op. */
    echsnitrickSetFlowPassthrough(
        fixture.t, lwip_htonl(kClientAddr), lwip_htonl(kServerAddr), kClientPort, kServerPort, flow.generation + 1000U);
    require(findClientFlow(&fixture, &flow), "a stale timeout removed the live flow");

    fixtureDestroy(&fixture);
}

static void testLaterTrafficDuringDelay(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = 0;

    startSuccessfulDelay(&fixture, hello, &hello_len);

    uint16_t first_len = (uint16_t) (hello_len / 2U);

    /* An exact retransmission of a still-pending original may be swallowed. */
    require(feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq, TCP_ACK | TCP_PSH, hello, first_len)),
            "an exact retransmission was not handled");
    require(forwarded_count == 1, "an exact retransmission of a pending original was forwarded");

    /* ACK-only traffic passes. */
    require(feedUpstream(&fixture, makeClientPacket(&fixture, kClientHelloSeq + hello_len, TCP_ACK, NULL, 0)),
            "ACK-only traffic during the delay was not handled");
    require(forwarded_count == 2, "ACK-only traffic during the delay was swallowed");

    /* Unrelated later application data passes. */
    uint8_t later[16];
    memorySet(later, 0x7E, sizeof(later));
    require(
        feedUpstream(&fixture,
                     makeClientPacket(&fixture, kClientHelloSeq + hello_len, TCP_ACK | TCP_PSH, later, sizeof(later))),
        "later application data was not handled");
    require(forwarded_count == 3, "later application data during the delay was swallowed");

    /* A partial overlap cannot be classified, so it must fail open. */
    require(feedUpstream(
                &fixture,
                makeClientPacket(&fixture, kClientHelloSeq, TCP_ACK | TCP_PSH, hello, (uint16_t) (first_len / 2U))),
            "a partial overlap was not handled");
    require(forwarded_count == 4, "a partial overlap was swallowed instead of failing open");

    fixtureDestroy(&fixture);
}

static void testIdleExpiryCannotDestroyDelayedOriginals(test_env_t *env)
{
    resetCaptures();

    test_fixture_t          fixture = fixtureCreate(env);
    ipmanipulator_tstate_t *state   = tunnelGetState(fixture.t);
    uint8_t                 hello[1024];
    uint16_t                hello_len = buildMatchingClientHello(hello, sizeof(hello));

    state->trick_ech_sni_shard1_delay_ms = kFlowIdleTimeoutMs + 1000U;
    state->trick_ech_sni_shard2_delay_ms = 500U;

    openFlow(&fixture, TCP_SYN);
    feedClientHelloSegments(&fixture, hello, hello_len, 2, false);

    require(forwarded_count == 1, "the delayed-release expiry fixture did not emit its fake inner packet");
    require(timed_message_count == 1 && timed_messages[0].delay_ms == state->trick_ech_sni_shard1_delay_ms,
            "the delayed-release expiry fixture did not retain its configured first delay");

    ipmanipulator_flow_key_t key =
        ipmanipulatorFlowKeyMake(lwip_htonl(kClientAddr), kClientPort, lwip_htonl(kServerAddr), kServerPort);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->echsni_table, &key);
    require(shard != NULL, "could not lock the delayed-release flow shard");

    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->echsni_table, shard, &key);
    require(entry != NULL && entry->deadline_ms > getTickMS() + kFlowIdleTimeoutMs,
            "a releasing ECH flow did not retain enough watchdog slack");

    uint32_t expired = ipmanipulatorFlowShardExpire(
        &state->echsni_table, shard, getTickMS() + kFlowIdleTimeoutMs + 1U, kIpManipulatorFlowCleanupBudget);
    require(expired == 0 && ipmanipulatorFlowShardFind(&state->echsni_table, shard, &key) != NULL,
            "idle cleanup destroyed originals before their configured release");
    ipmanipulatorFlowShardUnlock(shard);

    runTimedMessage(0);
    require(timed_message_count == 2, "the surviving flow did not schedule its second release phase");
    runTimedMessage(1);
    require(forwarded_count == 3, "the surviving delayed flow did not release both originals");

    shard = ipmanipulatorFlowTableLockShard(&state->echsni_table, &key);
    entry = ipmanipulatorFlowShardFind(&state->echsni_table, shard, &key);
    require(entry != NULL && entry->deadline_ms != UINT64_MAX,
            "normal idle expiry was not restored after the final release");
    ipmanipulatorFlowShardUnlock(shard);

    fixtureDestroy(&fixture);
}

static void testTimerCleanupDrainsPendingOriginals(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = 0;

    startSuccessfulDelay(&fixture, hello, &hello_len);
    discard hello_len;

    line_refc_t refc = fixture.line->refc;

    cleanupTimedMessage(0);
    require(fixture.line->refc == refc, "timer cleanup changed the packet-line reference count");

    ipmanipulator_echsni_flow_t flow = {0};
    require(findClientFlow(&fixture, &flow), "timer cleanup removed the flow");
    require(flow.pending_original_count == 0 && flow.phase == kIpManipulatorEchSniFlowPhasePassthrough,
            "target-worker timer cleanup did not drain the originals");
    require(forwarded_count == 3, "target-worker timer cleanup did not emit both originals");

    fixtureDestroy(&fixture);
}

static void testDroppedScheduleReleasesEchOriginals(test_env_t *env)
{
    resetCaptures();

    test_fixture_t fixture = fixtureCreate(env);
    uint8_t        hello[1024];
    uint16_t       hello_len = 0;

    g_schedule_should_fail = true;
    hello_len              = buildMatchingClientHello(hello, sizeof(hello));
    openFlow(&fixture, TCP_SYN);
    feedClientHelloSegments(&fixture, hello, hello_len, 2, false);

    uint16_t first_len = (uint16_t) (hello_len / 2U);
    require(timed_message_count == 0, "a rejected ECH release schedule was recorded as accepted");
    require(forwarded_count == 3, "a rejected ECH release schedule did not flush both originals");
    require(forwarded_packets[1].seq == kClientHelloSeq && forwarded_packets[1].payload_len == first_len,
            "rejected ECH release reordered the first original");
    require(forwarded_packets[2].seq == (uint32_t) kClientHelloSeq + first_len,
            "rejected ECH release reordered the second original");

    ipmanipulator_echsni_flow_t flow = {0};
    require(findClientFlow(&fixture, &flow), "rejected ECH release removed the flow");
    require(flow.phase == kIpManipulatorEchSniFlowPhasePassthrough && flow.pending_original_count == 0,
            "rejected ECH release left pending originals");

    fixtureDestroy(&fixture);
}

static void testFlowLimitFailsOpen(test_env_t *env)
{
    resetCaptures();

    test_fixture_t          fixture  = fixtureCreate(env);
    ipmanipulator_tstate_t *state    = tunnelGetState(fixture.t);
    uint32_t                admitted = 0;

    /*
     * Admission is bounded per shard, so this only proves the table refuses to
     * grow past its configured limit and keeps failing open afterwards.
     */
    for (uint32_t i = 0; i < kIpManipulatorFlowLimitMin * 4U; ++i)
    {
        forwarded_count = 0;
        discard feedUpstream(
            &fixture,
            makeTcpPacket(
                fixture.line, kClientAddr, (uint16_t) (20000U + i), kServerAddr, kServerPort, 1, TCP_SYN, NULL, 0));
        admitted = ipmanipulatorFlowTableCount(&state->echsni_table);
        require(admitted <= state->trick_stateful_flow_limit, "the ECH flow table grew past its configured limit");
    }

    require(admitted > 0, "the ECH flow table admitted nothing at all");

    fixtureDestroy(&fixture);
}

int main(void)
{
    test_env_t env;
    envSetup(&env);

    testSegmentationMatrix(&env);
    testBoundarySplits(&env);
    testExactRetransmissionDuringIncompleteCapture(&env);
    testAckOnlyPacketsDoNotDisableCapture(&env);
    testSeventeenthSegmentFailsOpen(&env);
    testSequenceGapFailsOpen(&env);
    testCaptureOutOfOrderAndPartialOverlapFailOpen(&env);
    testSynClassification(&env);
    testInnerSniMatchingMatrix(&env);
    testForeignWorkerReleaseDrainForwardsOnOwner(&env);
    testGracefulCloseDrainsForeignOriginalOnOwner(&env);
    testDownstreamRstDuringSecondPhaseEmission(&env);
    testDeadLineDuringSecondPhaseDrains(&env);
    testCloseDuringFakeInnerEmission(&env);
    testDownstreamRstBeforeFirstRelease(&env);
    testDownstreamFinBetweenReleases(&env);
    testGracefulFinFlushesPendingOriginals(&env);
    testGracefulFinAfterPartialReleaseFlushesRemainder(&env);
    testRstStillDiscardsPendingOriginals(&env);
    testUpstreamFinFlushesIncompleteCapture(&env);
    testDownstreamRstCancelsIncompleteCapture(&env);
    testTupleReuseInvalidatesOldGeneration(&env);
    testTupleReuseCancelsIncompleteCapture(&env);
    testCaptureTimeoutReleasesAndFailsOpen(&env);
    testLaterTrafficDuringDelay(&env);
    testIdleExpiryCannotDestroyDelayedOriginals(&env);
    testTimerCleanupDrainsPendingOriginals(&env);
    testDroppedScheduleReleasesEchOriginals(&env);
    testFlowLimitFailsOpen(&env);

    envTeardown(&env);
    printf("ALL unit tests passed!\n");
    return 0;
}
