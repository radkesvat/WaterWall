#include "IpManipulator/structure.h"
#include "iowatcher.h"
#include "tricks/firstsni/trick.h"
#include "tricks/overlapsni/trick.h"
#include "tricks/smugglesni/trick.h"

static void require(bool condition, const char *message);

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    master_pool_t *messages_master;
    buffer_pool_t *buffer_pool;
    buffer_pool_t *buffer_pools[1];
    wloop_t       *loops[1];
    worker_t       workers[1];
} test_env_t;

static void envSetup(test_env_t *env)
{
    memoryZero(env, sizeof(*env));
    env->large_master    = masterpoolCreateWithCapacity(32);
    env->small_master    = masterpoolCreateWithCapacity(32);
    env->messages_master = masterpoolCreateWithCapacity(32);
    workerMessagesInstallMasterPoolCallbacks(env->messages_master);
    env->buffer_pool     = bufferpoolCreate(env->large_master, env->small_master, 32, 8192, 4096);
    env->buffer_pools[0] = env->buffer_pool;

    env->loops[0] = wloopCreate(0, env->buffer_pool, 0);
    iowatcherInit(env->loops[0]);

    env->workers[0].wid            = 0;
    env->workers[0].loop           = env->loops[0];
    env->workers[0].buffer_pool    = env->buffer_pool;
    env->workers[0].has_event_loop = true;
    workerMessagesInit(&env->workers[0]);

    GSTATE.workers                       = env->workers;
    GSTATE.workers_count                 = 2;
    GSTATE.shortcut_buffer_pools         = env->buffer_pools;
    GSTATE.shortcut_loops                = env->loops;
    GSTATE.masterpool_buffer_pools_large = env->large_master;
    GSTATE.masterpool_buffer_pools_small = env->small_master;
    GSTATE.masterpool_messages           = env->messages_master;
    tl_wid                               = 0;

    /* Bounded flow tables refuse to run without a secure hash seed. */
    require(globalstateInitializeSecureRandom(), "the operating system random source is unavailable");
}

static void envTeardown(test_env_t *env)
{
    globalstateDestroySecureRandom();
    workerMessagesDestroy(&env->workers[0]);
    wloopDestroy(&env->loops[0]);

    GSTATE.workers                       = NULL;
    GSTATE.workers_count                 = 0;
    GSTATE.shortcut_buffer_pools         = NULL;
    GSTATE.shortcut_loops                = NULL;
    GSTATE.masterpool_buffer_pools_large = NULL;
    GSTATE.masterpool_buffer_pools_small = NULL;
    GSTATE.masterpool_messages           = NULL;

    bufferpoolDestroy(env->buffer_pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolMakeEmpty(env->messages_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
    masterpoolDestroy(env->messages_master);
}

enum
{
    kMaxReceivedPackets = 32
};

typedef struct received_packet_record_s
{
    uint32_t seq;
    uint16_t payload_len;
    uint16_t ip_len;
    uint8_t  tcp_flags;
    uint8_t  payload[2048];
} received_packet_record_t;

static uint32_t                 generator_calls;
static uint32_t                 normal_packets_count;
static received_packet_record_t normal_packets[kMaxReceivedPackets];
static uint32_t                 real_packets_count;
static received_packet_record_t real_packets[kMaxReceivedPackets];
static uint32_t                 generated_hello_len;
static uint32_t                 generated_record_len;
static uint8_t                  generated_hello_pattern = 0xA5;

typedef enum test_tls_generator_mode_e
{
    kTestTlsGeneratorModeValid = 0,
    kTestTlsGeneratorModeTrailingBytes
} test_tls_generator_mode_e;

static test_tls_generator_mode_e generator_mode;

sbuf_t *tlsclientTunnelGenerateClientHello(tunnel_t *instance, line_t *caller_line, const uint8_t *hostname,
                                           uint32_t hostname_length);

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

sbuf_t *tlsclientTunnelGenerateClientHello(tunnel_t *instance, line_t *caller_line, const uint8_t *hostname,
                                           uint32_t hostname_length)
{
    discard instance;
    discard caller_line;
    discard hostname;
    discard hostname_length;
    generator_calls++;

    sbuf_t  *hello      = bufferpoolGetSmallBuffer(getWorkerBufferPool(getWID()));
    uint32_t hello_len  = generated_hello_len;
    uint32_t record_len = hello_len;
    sbufSetLength(hello, hello_len);

    uint8_t *buf = sbufGetMutablePtr(hello);
    memorySet(buf, generated_hello_pattern, hello_len);

    if (generator_mode == kTestTlsGeneratorModeTrailingBytes)
    {
        require(generated_record_len < hello_len, "trailing-bytes generator record is not shorter than its buffer");
        record_len = generated_record_len;
    }

    if (record_len >= 5 + 4 + 34 + 2 + 2 + 1 + 2 + 9)
    {
        uint16_t record_payload_len = (uint16_t) (record_len - 5);
        uint32_t client_hello_len   = record_len - 9;

        buf[0] = 0x16;
        buf[1] = 0x03;
        buf[2] = 0x03;
        PUT_BE16(buf + 3, record_payload_len);
        buf[5] = 0x01;
        PUT_BE24(buf + 6, client_hello_len);
        buf[9]  = 0x03;
        buf[10] = 0x03;
        memorySet(buf + 11, 0x11, 32);
        buf[43] = 0; /* session id len */
        PUT_BE16(buf + 44, 2);
        PUT_BE16(buf + 46, 0x002f);
        buf[48] = 1;
        buf[49] = 0;

        const char *fake_name     = "fake.example";
        uint16_t    fake_name_len = 12;
        uint16_t    sni_list_len  = 3 + fake_name_len;
        uint16_t    ext_data_len  = 2 + sni_list_len;
        uint16_t    ext_len       = (uint16_t) (record_len - 52);

        PUT_BE16(buf + 50, ext_len);

        /* Server Name extension */
        PUT_BE16(buf + 52, 0x0000);
        PUT_BE16(buf + 54, ext_data_len);
        PUT_BE16(buf + 56, sni_list_len);
        buf[58] = 0;
        PUT_BE16(buf + 59, fake_name_len);
        memoryCopy(buf + 61, fake_name, fake_name_len);

        uint32_t sni_ext_total_len = 4 + ext_data_len;
        if (ext_len >= sni_ext_total_len + 4)
        {
            uint16_t pad_ext_len = ext_len - (uint16_t) sni_ext_total_len - 4;
            uint8_t *pad_ptr     = buf + 52 + sni_ext_total_len;
            PUT_BE16(pad_ptr, 0x0015);
            PUT_BE16(pad_ptr + 2, pad_ext_len);
            memoryZero(pad_ptr + 4, pad_ext_len);
        }
    }

    return hello;
}

static void recordReceivedPacket(received_packet_record_t *records, uint32_t *count, const sbuf_t *buf)
{
    if (*count >= kMaxReceivedPackets)
    {
        return;
    }

    received_packet_record_t *rec      = &records[*count];
    const uint8_t            *packet   = sbufGetRawPtr(buf);
    const struct ip_hdr      *ip       = (const struct ip_hdr *) packet;
    uint16_t                  ip_len   = lwip_ntohs(IPH_LEN(ip));
    uint16_t                  ip_hlen  = (uint16_t) (IPH_HL(ip) * 4U);
    const struct tcp_hdr     *tcp      = (const struct tcp_hdr *) (packet + ip_hlen);
    uint16_t                  tcp_hlen = (uint16_t) (TCPH_HDRLEN(tcp) * 4U);

    rec->ip_len      = ip_len;
    rec->seq         = lwip_ntohl(tcp->seqno);
    rec->payload_len = (uint16_t) (ip_len - ip_hlen - tcp_hlen);
    rec->tcp_flags   = TCPH_FLAGS(tcp);

    if (rec->payload_len > 0)
    {
        uint32_t copy_len = min((uint32_t) rec->payload_len, (uint32_t) sizeof(rec->payload));
        memoryCopy(rec->payload, packet + ip_hlen + tcp_hlen, copy_len);
    }

    *count += 1;
}

static void receiveNormal(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    recordReceivedPacket(normal_packets, &normal_packets_count, buf);
    lineReuseBuffer(l, buf);
}

static void receiveReal(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    recordReceivedPacket(real_packets, &real_packets_count, buf);
    lineReuseBuffer(l, buf);
}

static line_t makeTestLine(void)
{
    line_t line = {0};
    atomicStoreRelaxed(&line.refc, 1);
    line.alive = true;
    line.wid   = 0;
    return line;
}

static sbuf_t *makeTcpPacketForSourcePort(uint16_t src_port, uint32_t seq, uint8_t flags, const uint8_t *payload,
                                          uint16_t payload_len)
{
    uint16_t packet_len = (uint16_t) (sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) + payload_len);
    sbuf_t  *buf        = bufferpoolGetSmallBuffer(getWorkerBufferPool(getWID()));
    sbufSetLength(buf, packet_len);

    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, packet_len);

    struct ip_hdr *ip = (struct ip_hdr *) packet;
    IPH_VHL_SET(ip, 4, sizeof(struct ip_hdr) / 4U);
    IPH_LEN_SET(ip, lwip_htons(packet_len));
    IPH_PROTO_SET(ip, IPPROTO_TCP);
    ip->src.addr  = PP_HTONL(LWIP_MAKEU32(10, 0, 0, 1));
    ip->dest.addr = PP_HTONL(LWIP_MAKEU32(10, 0, 0, 2));

    struct tcp_hdr *tcp = (struct tcp_hdr *) (packet + sizeof(struct ip_hdr));
    tcp->src            = lwip_htons(src_port);
    tcp->dest           = lwip_htons(443);
    tcp->seqno          = lwip_htonl(seq);
    TCPH_HDRLEN_FLAGS_SET(tcp, sizeof(struct tcp_hdr) / 4U, flags);

    if (payload_len > 0 && payload != NULL)
    {
        memoryCopy(packet + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr), payload, payload_len);
    }

    return buf;
}

static sbuf_t *makeTcpPacketWithSeq(uint32_t seq, uint8_t flags, const uint8_t *payload, uint16_t payload_len)
{
    return makeTcpPacketForSourcePort(12345, seq, flags, payload, payload_len);
}

static uint16_t buildTlsClientHelloPayload(uint8_t *buf, uint16_t total_len, const char *sni)
{
    require(total_len >= 5 + 4 + 34 + 2 + 2 + 1 + 2 + 9, "total_len too small for valid ClientHello");

    uint16_t sni_len            = (uint16_t) stringLength(sni);
    uint16_t record_payload_len = (uint16_t) (total_len - 5);
    uint32_t client_hello_len   = total_len - 9;

    memoryZero(buf, total_len);
    buf[0] = 0x16;
    buf[1] = 0x03;
    buf[2] = 0x03;
    PUT_BE16(buf + 3, record_payload_len);
    buf[5] = 0x01;
    PUT_BE24(buf + 6, client_hello_len);
    buf[9]  = 0x03;
    buf[10] = 0x03;
    memorySet(buf + 11, 0x77, 32);
    buf[43] = 0;
    PUT_BE16(buf + 44, 2);
    PUT_BE16(buf + 46, 0x002f);
    buf[48] = 1;
    buf[49] = 0;

    uint16_t ext_len = (uint16_t) (total_len - 52);
    PUT_BE16(buf + 50, ext_len);

    /* Server Name extension */
    uint16_t sni_ext_payload_len = (uint16_t) (5 + sni_len);
    PUT_BE16(buf + 52, 0x0000);
    PUT_BE16(buf + 54, sni_ext_payload_len);
    PUT_BE16(buf + 56, (uint16_t) (3 + sni_len));
    buf[58] = 0;
    PUT_BE16(buf + 59, sni_len);
    memoryCopy(buf + 61, sni, sni_len);

    uint32_t sni_ext_total_len = 4 + sni_ext_payload_len;
    if (ext_len >= sni_ext_total_len + 4)
    {
        uint16_t pad_ext_len = ext_len - (uint16_t) sni_ext_total_len - 4;
        uint8_t *pad_ptr     = buf + 52 + sni_ext_total_len;
        PUT_BE16(pad_ptr, 0x0015);
        PUT_BE16(pad_ptr + 2, pad_ext_len);
        memoryZero(pad_ptr + 4, pad_ext_len);
    }

    return total_len;
}

static uint16_t buildTlsClientHelloPayloadWithLeadingPadding(uint8_t *buf, uint16_t total_len, const char *sni,
                                                             uint16_t leading_padding_len)
{
    uint16_t sni_len      = (uint16_t) stringLength(sni);
    uint32_t required_len = 52U + 4U + leading_padding_len + 4U + 5U + sni_len;

    require(total_len == required_len, "leading-padding ClientHello size mismatch");
    memoryZero(buf, total_len);

    buf[0] = 0x16;
    buf[1] = 0x03;
    buf[2] = 0x03;
    PUT_BE16(buf + 3, (uint16_t) (total_len - 5U));
    buf[5] = 0x01;
    PUT_BE24(buf + 6, total_len - 9U);
    buf[9]  = 0x03;
    buf[10] = 0x03;
    memorySet(buf + 11, 0x55, 32);
    buf[43] = 0;
    PUT_BE16(buf + 44, 2);
    PUT_BE16(buf + 46, 0x002f);
    buf[48] = 1;
    buf[49] = 0;
    PUT_BE16(buf + 50, (uint16_t) (total_len - 52U));

    uint8_t *extension = buf + 52;
    PUT_BE16(extension, 0x0015);
    PUT_BE16(extension + 2, leading_padding_len);

    extension += 4U + leading_padding_len;
    PUT_BE16(extension, 0x0000);
    PUT_BE16(extension + 2, (uint16_t) (5U + sni_len));
    PUT_BE16(extension + 4, (uint16_t) (3U + sni_len));
    extension[6] = 0;
    PUT_BE16(extension + 7, sni_len);
    memoryCopy(extension + 9, sni, sni_len);

    return total_len;
}

static tunnel_t *createTestTunnel(tunnel_t *normal, tunnel_t *real)
{
    static char   fake_sni[]  = "fake.example";
    static char   real_name[] = "real-branch";
    static node_t real_node   = {.name = real_name};

    tunnel_t *t = memoryAllocateAlignedZero(sizeof(tunnel_t) + sizeof(ipmanipulator_tstate_t), kCpuLineCacheSize);
    require(t != NULL, "failed to allocate test tunnel");

    t->tstate_size                = sizeof(ipmanipulator_tstate_t);
    t->next                       = normal;
    normal->fnPayloadU            = receiveNormal;
    real->fnPayloadU              = receiveReal;
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    mutexInit(&state->tls_capture_mutex);
    state->tls_capture_slots_count = 16;
    state->tls_capture_slots = memoryAllocateZero(sizeof(*state->tls_capture_slots) * state->tls_capture_slots_count);
    state->tls_prestart_slots_count = 16;
    state->tls_prestart_slots =
        memoryAllocateZero(sizeof(*state->tls_prestart_slots) * state->tls_prestart_slots_count);

    state->trick_stateful_flow_limit = kIpManipulatorFlowLimitMin;
    require(firstsnitrickInitializeState(t), "failed to create the first-sni flow table");
    require(smugglesnitrickInitializeState(t), "failed to create the smuggle-sni flow table");
    require(overlapsnitrickInitializeState(t), "failed to create the overlap-sni flow table");
    state->trick_smuggle_sni_value        = fake_sni;
    state->trick_smuggle_sni_value_len    = (uint16_t) stringLength(state->trick_smuggle_sni_value);
    state->trick_real_sni_upstream_node   = &real_node;
    state->trick_real_sni_upstream_tunnel = real;
    state->trick_smuggle_sni_delay_ms     = 0;
    state->trick_smuggle_sni              = true;
    return t;
}

static void destroyTestTunnel(tunnel_t *t)
{
    ipmanipulatorDestroyTlsCaptureState(t);
    firstsnitrickDestroyState(t);
    smugglesnitrickDestroyState(t);
    overlapsnitrickDestroyState(t);
    memoryFreeAligned(t);
}

static void resetCounters(void)
{
    generator_calls      = 0;
    normal_packets_count = 0;
    real_packets_count   = 0;
    generator_mode       = kTestTlsGeneratorModeValid;
    generated_record_len = 0;
    memoryZero(normal_packets, sizeof(normal_packets));
    memoryZero(real_packets, sizeof(real_packets));
}

static void warmFlowForSourcePort(tunnel_t *t, line_t *line, uint16_t src_port, uint32_t start_seq)
{
    sbuf_t *syn = makeTcpPacketForSourcePort(src_port, start_seq, TCP_SYN, NULL, 0);
    require(! smugglesnitrickUpStreamPayload(t, line, syn), "SYN was consumed");
    lineReuseBuffer(line, syn);

    sbuf_t *ack = makeTcpPacketForSourcePort(src_port, start_seq + 1, TCP_ACK, NULL, 0);
    require(! smugglesnitrickUpStreamPayload(t, line, ack), "ACK was consumed");
    lineReuseBuffer(line, ack);
}

static void warmFlow(tunnel_t *t, line_t *line, uint32_t start_seq)
{
    warmFlowForSourcePort(t, line, 12345, start_seq);
}

/*
 * Snapshots the record for one source port out of the bounded flow table. The
 * copy is taken under the shard lock because an entry pointer is only valid
 * while its shard stays locked.
 */
static bool findFlowForSourcePort(ipmanipulator_tstate_t *state, uint16_t src_port, ipmanipulator_smuggle_flow_t *out)
{
    ipmanipulator_flow_key_t key = ipmanipulatorFlowKeyMake(
        PP_HTONL(LWIP_MAKEU32(10, 0, 0, 1)), src_port, PP_HTONL(LWIP_MAKEU32(10, 0, 0, 2)), 443);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(&state->smuggle_table, &key);
    bool                        found = false;

    if (shard == NULL)
    {
        return false;
    }

    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(&state->smuggle_table, shard, &key);
    if (entry != NULL)
    {
        *out  = *(ipmanipulator_smuggle_flow_t *) ipmanipulatorFlowEntryRecord(entry);
        found = out->src_port == src_port;
    }

    ipmanipulatorFlowShardUnlock(shard);
    return found;
}

static ipmanipulator_flow_table_t *delayTableForKind(ipmanipulator_tstate_t            *state,
                                                     ipmanipulator_delay_barrier_kind_e kind)
{
    switch (kind)
    {
    case kIpManipulatorDelayBarrierFirstSni:
        return &state->first_sni_table;
    case kIpManipulatorDelayBarrierSmuggleSni:
        return &state->smuggle_table;
    case kIpManipulatorDelayBarrierOverlapSni:
        return &state->overlap_table;
    default:
        return NULL;
    }
}

static ipmanipulator_delay_barrier_t *delayBarrierForKind(void *record, ipmanipulator_delay_barrier_kind_e kind)
{
    switch (kind)
    {
    case kIpManipulatorDelayBarrierFirstSni:
        return &((ipmanipulator_firstsni_flow_t *) record)->delay_barrier;
    case kIpManipulatorDelayBarrierSmuggleSni:
        return &((ipmanipulator_smuggle_flow_t *) record)->delay_barrier;
    case kIpManipulatorDelayBarrierOverlapSni:
        return &((ipmanipulator_overlap_flow_t *) record)->delay_barrier;
    default:
        return NULL;
    }
}

/* Keep these integration tests fast while still invoking the production timer runner. */
static void forceDelayBarrierDue(tunnel_t *t, uint16_t src_port, ipmanipulator_delay_barrier_kind_e kind)
{
    ipmanipulator_tstate_t  *state = tunnelGetState(t);
    ipmanipulator_flow_key_t key   = ipmanipulatorFlowKeyMake(
        PP_HTONL(LWIP_MAKEU32(10, 0, 0, 1)), src_port, PP_HTONL(LWIP_MAKEU32(10, 0, 0, 2)), 443);
    ipmanipulator_flow_table_t *table = delayTableForKind(state, kind);
    ipmanipulator_flow_shard_t *shard = ipmanipulatorFlowTableLockShard(table, &key);
    ipmanipulator_flow_entry_t *entry = ipmanipulatorFlowShardFind(table, shard, &key);

    require(entry != NULL, "ordered transcript flow disappeared");
    ipmanipulator_delay_barrier_t *barrier = delayBarrierForKind(ipmanipulatorFlowEntryRecord(entry), kind);
    require(barrier != NULL && barrier->timer_armed, "ordered transcript did not arm its timer");
    require(ipmanipulatorDelayBarrierHasPendingOrdered(barrier), "ordered transcript was not installed");

    uint64_t now_ms = getTickMS();
    for (uint32_t i = barrier->next_ordered_output; i < barrier->ordered_outputs_count; ++i)
    {
        barrier->ordered_outputs[i].due_ms = now_ms;
    }
    barrier->deadline_ms = now_ms;
    uint64_t generation  = barrier->generation;
    ipmanipulatorFlowShardUnlock(shard);

    ipmanipulatorDelayBarrierSchedule(t, &key, kind, generation, 0, 1);
    usleep(2000);
    wloopProcessEvents(GSTATE.shortcut_loops[0], 0);
}

static void requireNoActiveTlsSlots(const ipmanipulator_tstate_t *state)
{
    for (uint32_t i = 0; i < state->tls_capture_slots_count; ++i)
    {
        require(! state->tls_capture_slots[i].active, "capture slot remained active");
        require(state->tls_capture_slots[i].captured_packets_count == 0, "capture slot retained packets");
    }

    for (uint32_t i = 0; i < state->tls_prestart_slots_count; ++i)
    {
        require(! state->tls_prestart_slots[i].active, "prestart slot remained active");
        require(state->tls_prestart_slots[i].captured_packets_count == 0, "prestart slot retained packets");
    }
}

static void testFirstSniNonTlsBurstFallsThroughImmediately(void)
{
    tunnel_t  normal = {0};
    tunnel_t  real   = {0};
    tunnel_t *t      = createTestTunnel(&normal, &real);
    line_t    line   = makeTestLine();
    uint8_t   payload[128];

    memorySet(payload, 0x91, sizeof(payload));
    resetCounters();

    uint32_t seq = 4000;
    for (uint32_t i = 0; i < 17; ++i)
    {
        ipmanipulator_tls_capture_slot_t capture = {0};
        sbuf_t *packet = makeTcpPacketWithSeq(seq, TCP_ACK | TCP_PSH, payload, sizeof(payload));

        require(ipmanipulatorCaptureTlsClientHello(t, &line, packet, kIpManipulatorTlsCaptureKindFirstSni, &capture) ==
                    kIpManipulatorTlsCaptureStatusMiss,
                "first-sni delayed a non-TLS packet");
        tunnelNextUpStreamPayload(t, &line, packet);
        seq += sizeof(payload);
    }

    require(normal_packets_count == 17, "first-sni did not immediately forward the full non-TLS burst");
    for (uint32_t i = 0; i < normal_packets_count; ++i)
    {
        require(normal_packets[i].seq == 4000U + i * sizeof(payload), "first-sni reordered the non-TLS burst");
    }

    ipmanipulator_tstate_t *state = tunnelGetState(t);
    requireNoActiveTlsSlots(state);

    usleep(70000);
    wloopProcessEvents(GSTATE.shortcut_loops[0], 0);
    require(normal_packets_count == 17, "first-sni scheduled a prestart timeout for non-TLS traffic");
    requireNoActiveTlsSlots(state);

    destroyTestTunnel(t);
}

static void testFirstSniFragmentedClientHelloCapture(void)
{
    tunnel_t  normal          = {0};
    tunnel_t  real            = {0};
    tunnel_t *t               = createTestTunnel(&normal, &real);
    line_t    line            = makeTestLine();
    uint8_t   hello_buf[1705] = {0};
    uint16_t  hello_len       = buildTlsClientHelloPayload(hello_buf, sizeof(hello_buf), "first.example");
    uint16_t  first_len       = 900;
    uint16_t  second_len      = hello_len - first_len;
    uint32_t  first_seq       = 9000;
    ipmanipulator_tls_capture_slot_t capture = {0};

    resetCounters();

    sbuf_t *first = makeTcpPacketWithSeq(first_seq, TCP_ACK | TCP_PSH, hello_buf, first_len);
    require(ipmanipulatorCaptureTlsClientHello(t, &line, first, kIpManipulatorTlsCaptureKindFirstSni, &capture) ==
                kIpManipulatorTlsCaptureStatusPending,
            "first-sni did not start capture from a recognizable fragmented ClientHello");

    sbuf_t *second = makeTcpPacketWithSeq(first_seq + first_len, TCP_ACK | TCP_PSH, hello_buf + first_len, second_len);
    require(ipmanipulatorCaptureTlsClientHello(t, &line, second, kIpManipulatorTlsCaptureKindFirstSni, &capture) ==
                kIpManipulatorTlsCaptureStatusReady,
            "first-sni did not complete an in-order fragmented ClientHello");
    require(capture.captured_packets_count == 2, "first-sni captured the wrong segment count");
    require(capture.assembled_packet != NULL, "first-sni did not assemble the fragmented ClientHello");
    requireNoActiveTlsSlots(tunnelGetState(t));

    ipmanipulatorReleaseCapturedPacketsNormal(t, &capture);
    require(normal_packets_count == 2, "first-sni cleanup did not release both captured segments");
    require(normal_packets[0].seq == first_seq && normal_packets[1].seq == first_seq + first_len,
            "first-sni cleanup reordered the captured segments");

    destroyTestTunnel(t);
}

static void testFirstSniRejectsIpv4Fragments(void)
{
    tunnel_t  normal            = {0};
    tunnel_t  real              = {0};
    tunnel_t *t                 = createTestTunnel(&normal, &real);
    line_t    line              = makeTestLine();
    uint8_t   hello_buf[256]    = {0};
    uint16_t  hello_len         = buildTlsClientHelloPayload(hello_buf, sizeof(hello_buf), "fragment.example");
    uint16_t  fragment_fields[] = {IP_MF, 1U};

    resetCounters();

    for (uint32_t i = 0; i < ARRAY_SIZE(fragment_fields); ++i)
    {
        ipmanipulator_tls_capture_slot_t capture = {0};
        sbuf_t        *packet = makeTcpPacketWithSeq(12000U + i * hello_len, TCP_ACK | TCP_PSH, hello_buf, hello_len);
        struct ip_hdr *ip     = (struct ip_hdr *) sbufGetMutablePtr(packet);
        IPH_OFFSET_SET(ip, lwip_htons(fragment_fields[i]));

        require(ipmanipulatorCaptureTlsClientHello(t, &line, packet, kIpManipulatorTlsCaptureKindFirstSni, &capture) ==
                    kIpManipulatorTlsCaptureStatusMiss,
                i == 0 ? "first-sni entered TLS capture for an MF first fragment"
                       : "first-sni entered TLS capture for a nonzero-offset fragment");
        tunnelNextUpStreamPayload(t, &line, packet);
    }

    require(normal_packets_count == 2, "first-sni did not fail IPv4 fragments open in arrival order");
    require(normal_packets[0].seq == 12000U && normal_packets[1].seq == 12000U + hello_len,
            "first-sni fragment fail-open path changed packet order");
    requireNoActiveTlsSlots(tunnelGetState(t));

    destroyTestTunnel(t);
}

static void testFirstSniCompleteTranscriptOrdering(void)
{
    static char fake_sni[] = "fake.example";

    tunnel_t  normal         = {0};
    tunnel_t  real           = {0};
    tunnel_t *t              = createTestTunnel(&normal, &real);
    line_t    line           = makeTestLine();
    uint8_t   hello_buf[256] = {0};
    uint8_t   tail_payload   = 0x7E;
    uint16_t  hello_len      = buildTlsClientHelloPayload(hello_buf, sizeof(hello_buf), "real.example");
    uint32_t  start_seq      = 13000;

    ipmanipulator_tstate_t *state          = tunnelGetState(t);
    state->trick_first_sni_value           = fake_sni;
    state->trick_first_sni_value_len       = 12;
    state->trick_first_sni_count           = 3;
    state->trick_first_sni_replay_delay_ms = 10;
    state->trick_first_sni_final_delay_ms  = 10;
    state->trick_first_sni_ttl             = -1;

    resetCounters();

    sbuf_t *syn = makeTcpPacketWithSeq(start_seq, TCP_SYN, NULL, 0);
    require(! firstsnitrickUpStreamPayload(t, &line, syn), "first-sni consumed the opening SYN");
    lineReuseBuffer(&line, syn);

    uint32_t hello_seq = start_seq + 1U;
    require(firstsnitrickUpStreamPayload(
                t, &line, makeTcpPacketWithSeq(hello_seq, TCP_ACK | TCP_PSH, hello_buf, hello_len)),
            "first-sni did not consume the ClientHello transcript");
    require(normal_packets_count == 1, "first-sni did not emit exactly the immediate first replay");

    require(
        firstsnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(hello_seq + hello_len, TCP_ACK, &tail_payload, 1)),
        "first-sni did not retain the post-ClientHello tail");
    require(normal_packets_count == 1, "first-sni released the tail before transcript completion");

    forceDelayBarrierDue(t, 12345, kIpManipulatorDelayBarrierFirstSni);

    require(normal_packets_count == 5, "first-sni complete transcript emitted the wrong packet count");
    for (uint32_t i = 0; i < 3; ++i)
    {
        require(normal_packets[i].payload_len == hello_len, "first-sni replay length changed");
        require(memcmp(normal_packets[i].payload + 61, "fake.example", 12) == 0,
                "first-sni replay order did not keep all crafted hellos first");
    }
    require(normal_packets[3].payload_len == hello_len &&
                memcmp(normal_packets[3].payload + 61, "real.example", 12) == 0,
            "first-sni original ClientHello did not follow every crafted replay");
    require(normal_packets[4].seq == hello_seq + hello_len && normal_packets[4].payload_len == 1 &&
                normal_packets[4].payload[0] == tail_payload,
            "first-sni tail overtook the complete transcript");

    usleep(12000);
    wloopProcessEvents(GSTATE.shortcut_loops[0], 0);
    destroyTestTunnel(t);
}

static void testNonTlsCaptureFallsThrough(void)
{
    tunnel_t             normal = {0};
    tunnel_t             real   = {0};
    tunnel_t            *t      = createTestTunnel(&normal, &real);
    line_t               line   = makeTestLine();
    static const uint8_t http[] = "POST / HTTP/1.1\r\n";

    resetCounters();
    warmFlow(t, &line, 1000);
    sbuf_t *packet = makeTcpPacketWithSeq(1001, TCP_ACK, http, (uint16_t) (sizeof(http) - 1));
    require(! smugglesnitrickUpStreamPayload(t, &line, packet), "non-TLS capture packet was consumed");
    lineReuseBuffer(&line, packet);

    ipmanipulator_tstate_t      *state = tunnelGetState(t);
    ipmanipulator_smuggle_flow_t flow  = {0};
    require(findFlowForSourcePort(state, 12345, &flow), "non-TLS flow disappeared");
    require(flow.phase == kIpManipulatorSmuggleFlowPhasePassthrough, "non-TLS flow did not enter passthrough");
    require(generator_calls == 0, "non-TLS flow invoked ClientHello generation");
    require(real_packets_count == 0, "non-TLS capture packet went to real-SNI branch");
    require(normal_packets_count == 0, "non-TLS flow sent packets through helper internal schedule");

    destroyTestTunnel(t);
}

static void testSingleSegmentExactLengthSuccess(void)
{
    tunnel_t  normal         = {0};
    tunnel_t  real           = {0};
    tunnel_t *t              = createTestTunnel(&normal, &real);
    line_t    line           = makeTestLine();
    uint8_t   hello_buf[100] = {0};
    uint16_t  hello_len      = buildTlsClientHelloPayload(hello_buf, sizeof(hello_buf), "real.example");
    uint32_t  start_seq      = 5000;

    resetCounters();
    generated_hello_len = hello_len;
    warmFlow(t, &line, start_seq);

    uint32_t hello_seq = start_seq + 1;
    require(smugglesnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(hello_seq, TCP_ACK, hello_buf, hello_len)),
            "single segment ClientHello was not consumed");

    require(generator_calls == 1, "generator was not called once");
    require(real_packets_count == 1, "real packet count is not 1");
    require(real_packets[0].seq == hello_seq, "real packet seq mismatch");
    require(real_packets[0].payload_len == hello_len, "real packet payload len mismatch");

    require(normal_packets_count == 1, "normal packet count is not 1");
    require(normal_packets[0].seq == hello_seq, "normal fake packet seq mismatch");
    require(normal_packets[0].payload_len == hello_len, "normal fake packet payload len mismatch");

    destroyTestTunnel(t);
}

static void testTwoSegmentChromeSizedClientHello(void)
{
    tunnel_t  normal          = {0};
    tunnel_t  real            = {0};
    tunnel_t *t               = createTestTunnel(&normal, &real);
    line_t    line            = makeTestLine();
    uint8_t   hello_buf[1705] = {0};
    uint16_t  total_hello_len = buildTlsClientHelloPayload(hello_buf, sizeof(hello_buf), "chrome.real.example");
    uint16_t  seg0_len        = 1300;
    uint16_t  seg1_len        = total_hello_len - seg0_len;
    uint32_t  start_seq       = 10000;

    resetCounters();
    generated_hello_len = total_hello_len;
    warmFlow(t, &line, start_seq);

    uint32_t seg0_seq = start_seq + 1;
    uint32_t seg1_seq = seg0_seq + seg0_len;

    require(smugglesnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(seg0_seq, TCP_ACK, hello_buf, seg0_len)),
            "segment 0 was not consumed as pending");
    require(real_packets_count == 0, "segment 0 emitted real packet prematurely");
    require(normal_packets_count == 0, "segment 0 emitted fake packet prematurely");

    require(smugglesnitrickUpStreamPayload(
                t, &line, makeTcpPacketWithSeq(seg1_seq, TCP_ACK, hello_buf + seg0_len, seg1_len)),
            "segment 1 was not consumed on completion");

    require(generator_calls == 1, "generator was not called exactly once");
    require(real_packets_count == 2, "real packets count is not 2");
    require(real_packets[0].seq == seg0_seq && real_packets[0].payload_len == seg0_len, "real seg0 mismatch");
    require(real_packets[1].seq == seg1_seq && real_packets[1].payload_len == seg1_len, "real seg1 mismatch");

    require(normal_packets_count == 2, "normal fake packets count is not 2");
    require(normal_packets[0].seq == seg0_seq && normal_packets[0].payload_len == seg0_len, "fake seg0 mismatch");
    require(normal_packets[1].seq == seg1_seq && normal_packets[1].payload_len == seg1_len, "fake seg1 mismatch");

    /* Verify concatenated normal fake payloads match byte-for-byte with generated record */
    uint8_t concat_payloads[2000] = {0};
    memoryCopy(concat_payloads, normal_packets[0].payload, seg0_len);
    memoryCopy(concat_payloads + seg0_len, normal_packets[1].payload, seg1_len);

    uint8_t expected_gen_buf[2000] = {0};
    sbuf_t *expected_hello_sbuf    = smugglesnitrickGenerateTlsClientHello(t, &line);
    require(expected_hello_sbuf != NULL, "failed to generate expected TLS ClientHello");
    memoryCopy(expected_gen_buf, sbufGetRawPtr(expected_hello_sbuf), sbufGetLength(expected_hello_sbuf));
    reuseBuffer(expected_hello_sbuf);

    require(memcmp(concat_payloads, expected_gen_buf, total_hello_len) == 0,
            "concatenated fake segment payloads do not match generated ClientHello record byte-for-byte");

    destroyTestTunnel(t);
}

void ipmanipulatorReleasePendingCaptureOnWorker(worker_t *worker, void *arg1, void *arg2, void *arg3);

static void testNonZeroDelayBatchOrdering(void)
{
    tunnel_t  normal          = {0};
    tunnel_t  real            = {0};
    tunnel_t *t               = createTestTunnel(&normal, &real);
    line_t    line            = makeTestLine();
    uint8_t   hello_buf[1705] = {0};
    uint16_t  total_hello_len = buildTlsClientHelloPayload(hello_buf, sizeof(hello_buf), "delay.example");
    uint16_t  seg0_len        = 1000;
    uint16_t  seg1_len        = total_hello_len - seg0_len;
    uint32_t  start_seq       = 20000;
    uint8_t   tail_payload    = 0x6D;

    ipmanipulator_tstate_t *state     = tunnelGetState(t);
    state->trick_smuggle_sni_delay_ms = 50;

    resetCounters();
    generated_hello_len = total_hello_len;
    warmFlow(t, &line, start_seq);

    uint32_t seg0_seq = start_seq + 1;
    uint32_t seg1_seq = seg0_seq + seg0_len;

    require(smugglesnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(seg0_seq, TCP_ACK, hello_buf, seg0_len)),
            "seg0 failed");
    require(smugglesnitrickUpStreamPayload(
                t, &line, makeTcpPacketWithSeq(seg1_seq, TCP_ACK, hello_buf + seg0_len, seg1_len)),
            "seg1 failed");

    /* Prior to processing the timer event, real packets were sent but fake batch segments are delayed in queue */
    require(generator_calls == 1, "generator count != 1");
    require(real_packets_count == 2, "real packets != 2");
    require(normal_packets_count == 0, "fake batch segments emitted before timer expiry");

    require(
        smugglesnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(seg1_seq + seg1_len, TCP_ACK, &tail_payload, 1)),
        "smuggle-sni did not retain the post-ClientHello tail");
    require(normal_packets_count == 0, "smuggle-sni released the tail before the fake transcript");

    forceDelayBarrierDue(t, 12345, kIpManipulatorDelayBarrierSmuggleSni);

    /* The production timer emits the complete fake transcript, then the queued tail. */
    require(normal_packets_count == 3, "smuggle-sni transcript and tail emitted the wrong packet count");
    require(normal_packets[0].seq == seg0_seq && normal_packets[0].payload_len == seg0_len, "fake seg0 order mismatch");
    require(normal_packets[1].seq == seg1_seq && normal_packets[1].payload_len == seg1_len, "fake seg1 order mismatch");
    require(normal_packets[2].seq == seg1_seq + seg1_len && normal_packets[2].payload_len == 1 &&
                normal_packets[2].payload[0] == tail_payload,
            "smuggle-sni tail overtook the generated fake transcript");

    usleep(52000);
    wloopProcessEvents(GSTATE.shortcut_loops[0], 0);
    destroyTestTunnel(t);
}

static void testOverlapSniCompleteTranscriptOrdering(void)
{
    static char fake_sni[] = "fake.example";

    enum
    {
        kLeadingPaddingLen = 160,
        kHelloLen          = 245,
        kHeldLen           = 200,
        kGeneratedHelloLen = 180
    };

    tunnel_t  normal               = {0};
    tunnel_t  real                 = {0};
    tunnel_t *t                    = createTestTunnel(&normal, &real);
    line_t    line                 = makeTestLine();
    uint8_t   hello_buf[kHelloLen] = {0};
    uint8_t   tail_payload         = 0x4B;
    uint32_t  start_seq            = 27000;
    uint32_t  hello_seq            = start_seq + 1U;
    uint16_t  current_len          = kHelloLen - kHeldLen;

    buildTlsClientHelloPayloadWithLeadingPadding(
        hello_buf, sizeof(hello_buf), "overlap.real.example", kLeadingPaddingLen);

    ipmanipulator_tstate_t *state              = tunnelGetState(t);
    state->trick_overlap_sni_value             = fake_sni;
    state->trick_overlap_sni_value_len         = 12;
    state->trick_overlap_sni_delay_ms          = 1;
    state->trick_overlap_sni_syn_ttl           = -1;
    state->trick_overlap_sni_tls_client_tunnel = t;
    generated_hello_len                        = kGeneratedHelloLen;

    resetCounters();
    generated_hello_len = kGeneratedHelloLen;

    require(overlapsnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(start_seq, TCP_SYN, NULL, 0)),
            "overlap-sni did not process the opening SYN");
    require(overlapsnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(hello_seq, TCP_ACK, NULL, 0)),
            "overlap-sni did not process the warmup ACK");
    require(normal_packets_count == 2, "overlap-sni warmup output count mismatch");

    resetCounters();
    generated_hello_len = kGeneratedHelloLen;

    require(overlapsnitrickUpStreamPayload(
                t, &line, makeTcpPacketWithSeq(hello_seq, TCP_ACK | TCP_PSH, hello_buf, kHeldLen)),
            "overlap-sni did not retain the third packet");
    require(normal_packets_count == 0, "overlap-sni emitted the held packet prematurely");

    require(
        overlapsnitrickUpStreamPayload(
            t, &line, makeTcpPacketWithSeq(hello_seq + kHeldLen, TCP_ACK | TCP_PSH, hello_buf + kHeldLen, current_len)),
        "overlap-sni did not construct its transcript from the held pair");
    require(generator_calls == 1, "overlap-sni did not generate one fake ClientHello");
    require(normal_packets_count == 2, "overlap-sni did not emit exactly its two immediate transcript packets");
    require(normal_packets[0].seq == hello_seq && normal_packets[0].payload_len == kGeneratedHelloLen,
            "overlap-sni real prefix was not first");
    require(normal_packets[1].seq == hello_seq - 1U && normal_packets[1].payload_len == 0 &&
                normal_packets[1].tcp_flags == TCP_SYN,
            "overlap-sni fake SYN was not second");

    require(overlapsnitrickUpStreamPayload(
                t, &line, makeTcpPacketWithSeq(hello_seq + kHelloLen, TCP_ACK, &tail_payload, 1)),
            "overlap-sni did not retain the post-transcript tail");
    require(normal_packets_count == 2, "overlap-sni released the tail before delayed transcript entries");

    forceDelayBarrierDue(t, 12345, kIpManipulatorDelayBarrierOverlapSni);

    require(normal_packets_count == 6, "overlap-sni complete transcript emitted the wrong packet count");
    require(normal_packets[2].seq == hello_seq && normal_packets[2].payload_len == kGeneratedHelloLen,
            "overlap-sni generated ClientHello was not third");
    require(normal_packets[3].seq == hello_seq + kGeneratedHelloLen &&
                normal_packets[3].payload_len == kHeldLen - kGeneratedHelloLen,
            "overlap-sni held-packet continuation was out of order");
    require(normal_packets[4].seq == hello_seq + kHeldLen && normal_packets[4].payload_len == current_len,
            "overlap-sni current-packet continuation was out of order");
    require(normal_packets[5].seq == hello_seq + kHelloLen && normal_packets[5].payload_len == 1 &&
                normal_packets[5].payload[0] == tail_payload,
            "overlap-sni tail overtook the complete generated transcript");

    usleep(3000);
    wloopProcessEvents(GSTATE.shortcut_loops[0], 0);
    destroyTestTunnel(t);
}

static void testPendingPrestartTimeoutEntersPassthrough(void)
{
    tunnel_t  normal       = {0};
    tunnel_t  real         = {0};
    tunnel_t *t            = createTestTunnel(&normal, &real);
    line_t    line         = makeTestLine();
    uint8_t   payload[128] = {0};
    uint32_t  start_seq    = 25000;
    uint32_t  payload_seq  = start_seq + 1;

    memorySet(payload, 0xC3, sizeof(payload));
    resetCounters();
    warmFlow(t, &line, start_seq);

    require(
        smugglesnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(payload_seq, TCP_ACK, payload, sizeof(payload))),
        "prestart packet was not consumed as pending");
    require(normal_packets_count == 0, "pending prestart packet was emitted before timeout");

    ipmanipulator_tstate_t *state = tunnelGetState(t);
    require(state->tls_prestart_slots[0].active, "prestart slot was not activated");
    require(state->tls_prestart_slots[0].captured_packets_count == 1, "prestart slot did not retain one packet");

    usleep(70000);
    wloopProcessEvents(GSTATE.shortcut_loops[0], 0);

    require(normal_packets_count == 1, "prestart timeout did not emit the held packet exactly once");
    require(normal_packets[0].seq == payload_seq && normal_packets[0].payload_len == sizeof(payload),
            "prestart timeout changed the held packet");

    ipmanipulator_smuggle_flow_t flow = {0};
    require(findFlowForSourcePort(state, 12345, &flow), "prestart timeout removed the flow");
    require(flow.phase == kIpManipulatorSmuggleFlowPhasePassthrough,
            "prestart timeout did not enter permanent passthrough");
    require(flow.delay_window_until_ms == 0, "prestart timeout retained a delay window");
    requireNoActiveTlsSlots(state);

    ipmanipulatorUpStreamPayload(
        t, &line, makeTcpPacketWithSeq(payload_seq + sizeof(payload), TCP_ACK, payload, sizeof(payload)));
    require(normal_packets_count == 2, "post-timeout packet was not forwarded immediately");
    requireNoActiveTlsSlots(state);
    require(generator_calls == 0, "generator was invoked after prestart timeout");

    destroyTestTunnel(t);
}

static void testPendingPrestartEvictionEntersPassthrough(void)
{
    tunnel_t  normal       = {0};
    tunnel_t  real         = {0};
    tunnel_t *t            = createTestTunnel(&normal, &real);
    line_t    line         = makeTestLine();
    uint8_t   payload[128] = {0};
    uint16_t  src_ports[]  = {12000, 12001, 12002};
    uint32_t  start_seqs[] = {31000, 32000, 33000};

    memorySet(payload, 0xD4, sizeof(payload));
    resetCounters();

    ipmanipulator_tstate_t *state   = tunnelGetState(t);
    state->tls_prestart_slots_count = 2;

    for (uint32_t i = 0; i < 2; ++i)
    {
        warmFlowForSourcePort(t, &line, src_ports[i], start_seqs[i]);
        require(smugglesnitrickUpStreamPayload(
                    t,
                    &line,
                    makeTcpPacketForSourcePort(src_ports[i], start_seqs[i] + 1, TCP_ACK, payload, sizeof(payload))),
                "prestart slot fill packet was not consumed");
    }

    require(normal_packets_count == 0, "prestart slot fill emitted a packet");

    warmFlowForSourcePort(t, &line, src_ports[2], start_seqs[2]);
    require(
        smugglesnitrickUpStreamPayload(
            t, &line, makeTcpPacketForSourcePort(src_ports[2], start_seqs[2] + 1, TCP_ACK, payload, sizeof(payload))),
        "replacement prestart packet was not consumed");

    require(normal_packets_count == 1, "prestart eviction did not emit the evicted packet exactly once");
    require(normal_packets[0].seq == start_seqs[0] + 1, "prestart eviction released the wrong packet");

    ipmanipulator_smuggle_flow_t evicted_flow = {0};
    require(findFlowForSourcePort(state, src_ports[0], &evicted_flow), "evicted prestart flow disappeared");
    require(evicted_flow.phase == kIpManipulatorSmuggleFlowPhasePassthrough,
            "prestart eviction did not enter permanent passthrough");
    require(evicted_flow.delay_window_until_ms == 0, "prestart eviction retained a delay window");

    uint32_t active_prestart_slots = 0;
    for (uint32_t i = 0; i < state->tls_prestart_slots_count; ++i)
    {
        ipmanipulator_tls_prestart_slot_t *slot = &state->tls_prestart_slots[i];
        if (slot->active)
        {
            active_prestart_slots++;
            require(slot->src_port != src_ports[0], "evicted tuple remained in a prestart slot");
            require(slot->captured_packets_count == 1, "active prestart slot owns an unexpected packet count");
        }
    }
    require(active_prestart_slots == 2, "prestart eviction did not preserve full slot occupancy");

    ipmanipulatorUpStreamPayload(
        t,
        &line,
        makeTcpPacketForSourcePort(
            src_ports[0], start_seqs[0] + 1 + sizeof(payload), TCP_ACK, payload, sizeof(payload)));
    require(normal_packets_count == 2, "post-eviction packet was not forwarded immediately");
    require(generator_calls == 0, "generator was invoked after prestart eviction");

    destroyTestTunnel(t);
}

static void testPendingCaptureTimeout(void)
{
    tunnel_t  normal          = {0};
    tunnel_t  real            = {0};
    tunnel_t *t               = createTestTunnel(&normal, &real);
    line_t    line            = makeTestLine();
    uint8_t   hello_buf[1500] = {0};
    uint16_t  total_len       = buildTlsClientHelloPayload(hello_buf, sizeof(hello_buf), "timeout.example");
    uint16_t  seg0_len        = 500;
    uint16_t  seg1_len        = total_len - seg0_len;
    uint32_t  start_seq       = 30000;

    resetCounters();
    generated_hello_len = total_len;
    warmFlow(t, &line, start_seq);

    uint32_t seg0_seq = start_seq + 1;
    uint32_t seg1_seq = seg0_seq + seg0_len;

    require(smugglesnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(seg0_seq, TCP_ACK, hello_buf, seg0_len)),
            "seg0 failed");
    require(normal_packets_count == 0, "pending seg0 emitted prematurely");

    /* Simulate capture timeout firing */
    ipmanipulator_tstate_t *state = tunnelGetState(t);
    state->tls_capture_slots[0].last_update_ms -= 2000; /* force expired tick */

    ipmanipulator_tls_capture_timeout_msg_t *msg = memoryAllocate(sizeof(*msg));
    *msg                                         = (ipmanipulator_tls_capture_timeout_msg_t) {
                                                .slot_index = 0,
                                                .generation = state->tls_capture_slots[0].generation,
    };

    ipmanipulatorReleasePendingCaptureOnWorker(NULL, t, msg, NULL);

    require(normal_packets_count == 1, "timeout did not release pending capture packet to normal branch");
    require(normal_packets[0].seq == seg0_seq && normal_packets[0].payload_len == seg0_len,
            "timed out packet payload mismatch");

    ipmanipulator_smuggle_flow_t flow = {0};
    require(findFlowForSourcePort(state, 12345, &flow), "timed-out flow disappeared");
    require(flow.phase == kIpManipulatorSmuggleFlowPhasePassthrough,
            "capture timeout did not enter permanent passthrough");
    require(flow.delay_window_until_ms == 0, "capture timeout retained a delay window");
    requireNoActiveTlsSlots(state);

    ipmanipulatorUpStreamPayload(t, &line, makeTcpPacketWithSeq(seg1_seq, TCP_ACK, hello_buf + seg0_len, seg1_len));
    require(normal_packets_count == 2, "continuation after timeout did not pass through to normal branch");

    ipmanipulatorUpStreamPayload(t, &line, makeTcpPacketWithSeq(seg0_seq, TCP_ACK, hello_buf, seg0_len));
    require(normal_packets_count == 3, "retransmission after timeout did not pass through to normal branch");
    requireNoActiveTlsSlots(state);
    require(generator_calls == 0, "generator was invoked after capture timeout");

    destroyTestTunnel(t);
}

static void testFinRstFlushesPendingCapture(void)
{
    tunnel_t  normal          = {0};
    tunnel_t  real            = {0};
    tunnel_t *t               = createTestTunnel(&normal, &real);
    line_t    line            = makeTestLine();
    uint8_t   hello_buf[1500] = {0};
    uint16_t  total_len       = buildTlsClientHelloPayload(hello_buf, sizeof(hello_buf), "fin.example");
    uint16_t  seg0_len        = 500;
    uint32_t  start_seq       = 40000;

    resetCounters();
    generated_hello_len = total_len;
    warmFlow(t, &line, start_seq);

    uint32_t seg0_seq = start_seq + 1;

    require(smugglesnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(seg0_seq, TCP_ACK, hello_buf, seg0_len)),
            "seg0 failed");
    require(normal_packets_count == 0, "pending seg0 emitted prematurely");

    /* Send upstream FIN on the flow while pending */
    uint32_t fin_seq = seg0_seq + seg0_len;
    sbuf_t  *fin     = makeTcpPacketWithSeq(fin_seq, TCP_FIN | TCP_ACK, NULL, 0);
    require(! smugglesnitrickUpStreamPayload(t, &line, fin), "FIN packet was consumed");
    lineReuseBuffer(&line, fin);

    require(normal_packets_count == 1, "FIN did not flush pending capture packet to normal branch before close");
    require(normal_packets[0].seq == seg0_seq && normal_packets[0].payload_len == seg0_len,
            "flushed packet payload mismatch");

    destroyTestTunnel(t);
}

static void testThreeSegmentSequenceWrapping(void)
{
    tunnel_t  normal          = {0};
    tunnel_t  real            = {0};
    tunnel_t *t               = createTestTunnel(&normal, &real);
    line_t    line            = makeTestLine();
    uint8_t   hello_buf[1500] = {0};
    uint16_t  total_len       = buildTlsClientHelloPayload(hello_buf, sizeof(hello_buf), "wrap.example");
    uint16_t  seg0_len        = 500;
    uint16_t  seg1_len        = 600;
    uint16_t  seg2_len        = total_len - seg0_len - seg1_len;
    uint32_t  start_seq       = UINT32_MAX - 300;

    resetCounters();
    generated_hello_len = total_len;
    warmFlow(t, &line, start_seq);

    uint32_t seg0_seq = start_seq + 1;
    uint32_t seg1_seq = seg0_seq + seg0_len;
    uint32_t seg2_seq = seg1_seq + seg1_len;

    require(smugglesnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(seg0_seq, TCP_ACK, hello_buf, seg0_len)),
            "seg0 failed");
    require(smugglesnitrickUpStreamPayload(
                t, &line, makeTcpPacketWithSeq(seg1_seq, TCP_ACK, hello_buf + seg0_len, seg1_len)),
            "seg1 failed");
    require(smugglesnitrickUpStreamPayload(
                t, &line, makeTcpPacketWithSeq(seg2_seq, TCP_ACK, hello_buf + seg0_len + seg1_len, seg2_len)),
            "seg2 failed");

    require(generator_calls == 1, "generator count != 1");
    require(real_packets_count == 3, "real packets != 3");
    require(real_packets[0].seq == seg0_seq && real_packets[0].payload_len == seg0_len, "real seg0 wrap mismatch");
    require(real_packets[1].seq == seg1_seq && real_packets[1].payload_len == seg1_len, "real seg1 wrap mismatch");
    require(real_packets[2].seq == seg2_seq && real_packets[2].payload_len == seg2_len, "real seg2 wrap mismatch");

    require(normal_packets_count == 3, "fake packets != 3");
    require(normal_packets[0].seq == seg0_seq && normal_packets[0].payload_len == seg0_len, "fake seg0 wrap mismatch");
    require(normal_packets[1].seq == seg1_seq && normal_packets[1].payload_len == seg1_len, "fake seg1 wrap mismatch");
    require(normal_packets[2].seq == seg2_seq && normal_packets[2].payload_len == seg2_len, "fake seg2 wrap mismatch");

    destroyTestTunnel(t);
}

static void testLongerGeneratedRecordFallsThrough(void)
{
    tunnel_t  normal         = {0};
    tunnel_t  real           = {0};
    tunnel_t *t              = createTestTunnel(&normal, &real);
    line_t    line           = makeTestLine();
    uint8_t   hello_buf[120] = {0};
    uint16_t  hello_len      = buildTlsClientHelloPayload(hello_buf, sizeof(hello_buf), "small.example");

    resetCounters();
    generated_hello_len = hello_len + 50; /* longer generated record */
    warmFlow(t, &line, 1000);

    require(smugglesnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(1001, TCP_ACK, hello_buf, hello_len)),
            "oversize fake ClientHello capture was not handled");

    require(generator_calls == 1, "generator retried");
    require(real_packets_count == 0, "real packet was emitted on fail open");
    require(normal_packets_count == 1, "normal fail open packet was not scheduled");
    require(normal_packets[0].payload_len == hello_len, "original payload len altered on fail open");

    destroyTestTunnel(t);
}

static void testShorterGeneratedRecordFallsThrough(void)
{
    tunnel_t  normal         = {0};
    tunnel_t  real           = {0};
    tunnel_t *t              = createTestTunnel(&normal, &real);
    line_t    line           = makeTestLine();
    uint8_t   hello_buf[120] = {0};
    uint16_t  hello_len      = buildTlsClientHelloPayload(hello_buf, sizeof(hello_buf), "small.example");

    resetCounters();
    generated_hello_len = hello_len - 20; /* shorter generated record */
    warmFlow(t, &line, 1000);

    require(smugglesnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(1001, TCP_ACK, hello_buf, hello_len)),
            "shorter fake ClientHello capture was not handled");

    require(generator_calls == 1, "generator retried");
    require(real_packets_count == 0, "real packet emitted on fail open");
    require(normal_packets_count == 1, "normal fail open packet not scheduled");
    require(normal_packets[0].payload_len == hello_len, "original payload len altered on fail open");

    destroyTestTunnel(t);
}

static void testGeneratedRecordWithTrailingBytesFailsOpen(void)
{
    tunnel_t  normal         = {0};
    tunnel_t  real           = {0};
    tunnel_t *t              = createTestTunnel(&normal, &real);
    line_t    line           = makeTestLine();
    uint8_t   hello_buf[140] = {0};
    uint16_t  hello_len      = buildTlsClientHelloPayload(hello_buf, sizeof(hello_buf), "trailing-fake.example");
    uint32_t  hello_seq      = 7001;

    resetCounters();
    generated_hello_len  = hello_len;
    generated_record_len = hello_len - 20;
    generator_mode       = kTestTlsGeneratorModeTrailingBytes;
    warmFlow(t, &line, hello_seq - 1);

    require(smugglesnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(hello_seq, TCP_ACK, hello_buf, hello_len)),
            "generated trailing-bytes failure did not consume the captured packet");

    require(generator_calls == 1, "trailing-bytes generator was not called exactly once");
    require(normal_packets_count == 1, "original packet was not emitted exactly once on fail open");
    require(normal_packets[0].seq == hello_seq && normal_packets[0].payload_len == hello_len,
            "fail-open packet changed sequence or payload length");
    require(real_packets_count == 0, "real-SNI branch received a packet after generated validation failed");

    ipmanipulator_tstate_t      *state = tunnelGetState(t);
    ipmanipulator_smuggle_flow_t flow  = {0};
    require(findFlowForSourcePort(state, 12345, &flow), "generated validation failure removed the flow");
    require(flow.phase == kIpManipulatorSmuggleFlowPhasePassthrough,
            "generated validation failure did not enter passthrough");
    require(flow.delay_window_until_ms == 0, "generated validation failure retained a delay window");
    requireNoActiveTlsSlots(state);

    destroyTestTunnel(t);
}

static void testTrailingPayloadAfterClientHello(void)
{
    tunnel_t  normal             = {0};
    tunnel_t  real               = {0};
    tunnel_t *t                  = createTestTunnel(&normal, &real);
    line_t    line               = makeTestLine();
    uint8_t   hello_buf[200]     = {0};
    uint16_t  record_len         = buildTlsClientHelloPayload(hello_buf, 100, "trail.example");
    uint16_t  extra_trailing_len = 50;
    uint16_t  total_segment_len  = record_len + extra_trailing_len;

    memorySet(hello_buf + record_len, 0xDE, extra_trailing_len);

    resetCounters();
    generated_hello_len = record_len;
    warmFlow(t, &line, 2000);

    require(smugglesnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(2001, TCP_ACK, hello_buf, total_segment_len)),
            "trailing payload ClientHello was not consumed");

    require(generator_calls == 1, "generator count != 1");
    require(real_packets_count == 1, "real packets != 1");
    require(real_packets[0].payload_len == total_segment_len, "real payload len mismatch");

    require(normal_packets_count == 1, "fake packets != 1");
    require(normal_packets[0].payload_len == total_segment_len, "fake payload len mismatch");

    /* Verify trailing 50 bytes are untouched in normal fake packet */
    require(memcmp(normal_packets[0].payload + record_len, hello_buf + record_len, extra_trailing_len) == 0,
            "trailing payload bytes were modified in fake packet");

    destroyTestTunnel(t);
}

static void testFragmentDiscontinuityFailsOpen(void)
{
    tunnel_t  normal          = {0};
    tunnel_t  real            = {0};
    tunnel_t *t               = createTestTunnel(&normal, &real);
    line_t    line            = makeTestLine();
    uint8_t   hello_buf[1500] = {0};
    uint16_t  total_len       = buildTlsClientHelloPayload(hello_buf, sizeof(hello_buf), "discont.example");
    uint16_t  seg0_len        = 500;
    uint32_t  start_seq       = 3000;

    resetCounters();
    generated_hello_len = total_len;
    warmFlow(t, &line, start_seq);

    uint32_t seg0_seq = start_seq + 1;
    uint32_t bad_seq  = seg0_seq + seg0_len + 100; /* sequence discontinuity */

    require(smugglesnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(seg0_seq, TCP_ACK, hello_buf, seg0_len)),
            "seg0 failed");

    require(smugglesnitrickUpStreamPayload(t, &line, makeTcpPacketWithSeq(bad_seq, TCP_ACK, hello_buf + seg0_len, 500)),
            "discontinuous seg1 was not consumed via bypass");

    require(real_packets_count == 0, "discontinuity emitted real packet");
    require(normal_packets_count == 2, "discontinuity did not schedule both packets in order on normal branch");
    require(normal_packets[0].seq == seg0_seq && normal_packets[0].payload_len == seg0_len, "held seg0 mismatch");
    require(normal_packets[1].seq == bad_seq && normal_packets[1].payload_len == 500, "triggering bad seg mismatch");

    destroyTestTunnel(t);
}

int main(void)
{
    checkSumInit();

    test_env_t env;
    envSetup(&env);

    testFirstSniNonTlsBurstFallsThroughImmediately();
    testFirstSniFragmentedClientHelloCapture();
    testFirstSniRejectsIpv4Fragments();
    testFirstSniCompleteTranscriptOrdering();
    testPendingPrestartTimeoutEntersPassthrough();
    testNonZeroDelayBatchOrdering();
    testOverlapSniCompleteTranscriptOrdering();
    testNonTlsCaptureFallsThrough();
    testSingleSegmentExactLengthSuccess();
    testLongerGeneratedRecordFallsThrough();
    testShorterGeneratedRecordFallsThrough();
    testGeneratedRecordWithTrailingBytesFailsOpen();
    testTrailingPayloadAfterClientHello();
    testTwoSegmentChromeSizedClientHello();
    testThreeSegmentSequenceWrapping();
    testFragmentDiscontinuityFailsOpen();
    testPendingPrestartEvictionEntersPassthrough();
    testPendingCaptureTimeout();
    testFinRstFlushesPendingCapture();

    envTeardown(&env);
    printf("ALL unit tests passed!\n");
    fflush(stdout);
    return 0;
}
