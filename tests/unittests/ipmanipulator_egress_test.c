#include "IpManipulator/structure.h"
#include "tricks/portghost/trick.h"
#include "tricks/protoswap/trick.h"
#include "tricks/sniblender/trick.h"
#include "tricks/tcpbitchange/trick.h"
#include "wchecksum.h"
#include "worker_registry_fixture.h"

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

enum
{
    kCapturedPackets = 32,
    /* Mirrors the low-RAM profile where the small and large pools are both 4096 bytes. */
    kTestSmallBuffer = 256,
    kTestLargeBuffer = 256
};

typedef struct test_env_s
{
    master_pool_t *large_master;
    master_pool_t *small_master;
    buffer_pool_t *buffer_pool;
    buffer_pool_t *buffer_pools[1];
    line_t        *line;
    uint16_t       original_mtu;
} test_env_t;

static sbuf_t   *captured[kCapturedPackets];
static uint32_t  captured_count;
static tunnel_t *init_targets[3];
static uint32_t  init_counts[3];

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
    return NULL;
}

static tunnel_t *createTestTunnel(void)
{
    tunnel_t *t = memoryAllocateAlignedZero(sizeof(tunnel_t) + sizeof(ipmanipulator_tstate_t), kCpuLineCacheSize);
    require(t != NULL, "failed to allocate test tunnel");

    t->tstate_size = sizeof(ipmanipulator_tstate_t);

    ipmanipulator_tstate_t *state      = tunnelGetState(t);
    state->trick_proto_swap_tcp_number = -1;
    state->trick_proto_swap_udp_number = -1;
    return t;
}

static void destroyTestTunnel(tunnel_t *t)
{
    memoryFreeAligned(t);
}

static void envSetup(test_env_t *env)
{
    memoryZero(env, sizeof(*env));
    env->large_master = masterpoolCreateWithCapacity(64);
    env->small_master = masterpoolCreateWithCapacity(64);
    env->buffer_pool  = bufferpoolCreate(env->large_master, env->small_master, 64, kTestLargeBuffer, kTestSmallBuffer);
    env->buffer_pools[0] = env->buffer_pool;

    GSTATE.shortcut_buffer_pools         = env->buffer_pools;
    GSTATE.masterpool_buffer_pools_large = env->large_master;
    GSTATE.masterpool_buffer_pools_small = env->small_master;
    GSTATE.workers_count                 = 2;
    testWorkerRegistryInstall(&g_test_worker_registry);
    env->original_mtu = GLOBAL_MTU_SIZE;
    GLOBAL_MTU_SIZE   = 1500;
    testWorkerBindWID(0);

    env->line = memoryAllocateZero(sizeof(line_t));
    require(env->line != NULL, "failed to allocate test line");
    atomicStoreRelaxed(&env->line->refc, 1);
    env->line->alive = true;
    env->line->wid   = 0;
}

static void recycleCaptured(test_env_t *env)
{
    for (uint32_t i = 0; i < captured_count; ++i)
    {
        if (captured[i] != NULL)
        {
            lineReuseBuffer(env->line, captured[i]);
            captured[i] = NULL;
        }
    }
    captured_count = 0;
}

static void envTeardown(test_env_t *env)
{
    recycleCaptured(env);

    GSTATE.shortcut_buffer_pools         = NULL;
    GSTATE.masterpool_buffer_pools_large = NULL;
    GSTATE.masterpool_buffer_pools_small = NULL;
    GSTATE.workers_count                 = 0;
    testWorkerRegistryRestore(&g_test_worker_registry);
    GLOBAL_MTU_SIZE = env->original_mtu;

    memoryFree(env->line);
    bufferpoolDestroy(env->buffer_pool);
    masterpoolMakeEmpty(env->large_master);
    masterpoolMakeEmpty(env->small_master);
    masterpoolDestroy(env->large_master);
    masterpoolDestroy(env->small_master);
}

static void capturePacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard t;
    discard l;

    require(captured_count < kCapturedPackets, "captured packet array overflow");
    captured[captured_count++] = buf;
}

static void captureFirstThenKillLine(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    capturePacket(t, l, buf);
    l->alive = false;
}

static sbuf_t *makeTcpPacket(test_env_t *env, uint16_t packet_len)
{
    require(packet_len >= sizeof(struct ip_hdr) + sizeof(struct tcp_hdr), "TCP test packet is too small");

    sbuf_t *buf = bufferpoolGetLargeBuffer(env->buffer_pool);
    buf         = sbufReserveSpace(buf, packet_len);
    sbufSetLength(buf, packet_len);

    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, packet_len);

    struct ip_hdr *ip = (struct ip_hdr *) packet;
    IPH_VHL_SET(ip, 4, sizeof(struct ip_hdr) / 4U);
    IPH_LEN_SET(ip, lwip_htons(packet_len));
    IPH_ID_SET(ip, lwip_htons(0x1234));
    IPH_TTL_SET(ip, 64);
    IPH_PROTO_SET(ip, IPPROTO_TCP);
    ip->src.addr  = PP_HTONL(LWIP_MAKEU32(10, 0, 0, 1));
    ip->dest.addr = PP_HTONL(LWIP_MAKEU32(10, 0, 0, 2));

    struct tcp_hdr *tcp = (struct tcp_hdr *) (packet + sizeof(struct ip_hdr));
    tcp->src            = lwip_htons(12345);
    tcp->dest           = lwip_htons(443);
    tcp->seqno          = lwip_htonl(1000);
    tcp->ackno          = lwip_htonl(2000);
    TCPH_HDRLEN_FLAGS_SET(tcp, sizeof(struct tcp_hdr) / 4U, TCP_ACK | TCP_PSH);
    tcp->wnd = lwip_htons(64240);

    uint32_t payload_offset = sizeof(struct ip_hdr) + sizeof(struct tcp_hdr);
    for (uint32_t i = payload_offset; i < packet_len; ++i)
    {
        packet[i] = (uint8_t) (i * 17U + 3U);
    }

    require(calcFullPacketChecksum(packet, packet_len), "failed to checksum TCP test packet");
    return buf;
}

static void setTcpFlags(sbuf_t *buf, uint8_t flags)
{
    struct ip_hdr  *ip          = (struct ip_hdr *) sbufGetMutablePtr(buf);
    struct tcp_hdr *tcp         = (struct tcp_hdr *) (sbufGetMutablePtr(buf) + IPH_HL_BYTES(ip));
    uint16_t        header_word = lwip_ntohs(tcp->_hdrlen_rsvd_flags);

    tcp->_hdrlen_rsvd_flags = lwip_htons((uint16_t) ((header_word & 0xFF00U) | flags));
    require(calcFullPacketChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf)), "failed to checksum TCP flags fixture");
}

static uint8_t getTcpFlags(const struct tcp_hdr *tcp)
{
    return (uint8_t) (lwip_ntohs(tcp->_hdrlen_rsvd_flags) & 0x00FFU);
}

static sbuf_t *makeUdpPacket(test_env_t *env, uint16_t packet_len)
{
    require(packet_len >= sizeof(struct ip_hdr) + sizeof(struct udp_hdr), "UDP test packet is too small");

    sbuf_t *buf = bufferpoolGetLargeBuffer(env->buffer_pool);
    buf         = sbufReserveSpace(buf, packet_len);
    sbufSetLength(buf, packet_len);

    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, packet_len);

    struct ip_hdr *ip = (struct ip_hdr *) packet;
    IPH_VHL_SET(ip, 4, sizeof(struct ip_hdr) / 4U);
    IPH_LEN_SET(ip, lwip_htons(packet_len));
    IPH_ID_SET(ip, lwip_htons(0x4321));
    IPH_TTL_SET(ip, 64);
    IPH_PROTO_SET(ip, IPPROTO_UDP);
    ip->src.addr  = PP_HTONL(LWIP_MAKEU32(10, 0, 0, 1));
    ip->dest.addr = PP_HTONL(LWIP_MAKEU32(10, 0, 0, 2));

    struct udp_hdr *udp = (struct udp_hdr *) (packet + sizeof(struct ip_hdr));
    udp->src            = lwip_htons(12345);
    udp->dest           = lwip_htons(443);
    udp->len            = lwip_htons((uint16_t) (packet_len - sizeof(struct ip_hdr)));

    for (uint32_t i = sizeof(struct ip_hdr) + sizeof(struct udp_hdr); i < packet_len; ++i)
    {
        packet[i] = (uint8_t) (i * 11U + 7U);
    }

    require(calcFullPacketChecksum(packet, packet_len), "failed to checksum UDP test packet");
    return buf;
}

static void requireValidIpv4HeaderChecksum(const sbuf_t *buf)
{
    sbuf_t *copy = sbufDuplicate((sbuf_t *) buf);
    require(copy != NULL, "failed to duplicate packet for IPv4 checksum verification");

    const struct ip_hdr *original = (const struct ip_hdr *) sbufGetRawPtr(buf);
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(copy), sbufGetLength(copy)),
            "failed to recalculate IPv4 header checksum");
    const struct ip_hdr *recalculated = (const struct ip_hdr *) sbufGetRawPtr(copy);
    require(IPH_CHKSUM(original) == IPH_CHKSUM(recalculated), "IPv4 header checksum is invalid");
    sbufDestroy(copy);
}

static void requireTcpChecksumMatchesRealProtocol(const sbuf_t *buf)
{
    const uint8_t        *packet = sbufGetRawPtr(buf);
    const struct ip_hdr  *ip     = (const struct ip_hdr *) packet;
    const struct tcp_hdr *tcp    = (const struct tcp_hdr *) (packet + IPH_HL_BYTES(ip));
    uint16_t              actual = tcp->chksum;

    sbuf_t *copy = sbufDuplicate((sbuf_t *) buf);
    require(copy != NULL, "failed to duplicate packet for TCP checksum verification");
    struct ip_hdr *copy_ip = (struct ip_hdr *) sbufGetMutablePtr(copy);
    IPH_PROTO_SET(copy_ip, IPPROTO_TCP);
    require(calcFullPacketChecksum(sbufGetMutablePtr(copy), sbufGetLength(copy)),
            "failed to calculate real-protocol TCP checksum");
    struct tcp_hdr *copy_tcp = (struct tcp_hdr *) (sbufGetMutablePtr(copy) + IPH_HL_BYTES(copy_ip));
    require(actual == copy_tcp->chksum, "TCP checksum was not calculated under the real protocol");
    sbufDestroy(copy);
}

static void testEgressOrderAndDownstreamRoundTrip(test_env_t *env)
{
    tunnel_t  next = {.fnPayloadU = capturePacket};
    tunnel_t  prev = {.fnPayloadD = capturePacket};
    tunnel_t *t    = createTestTunnel();
    t->next        = &next;
    t->prev        = &prev;

    ipmanipulator_tstate_t *state      = tunnelGetState(t);
    state->trick_source_port_ghost     = true;
    state->trick_dest_port_ghost       = true;
    state->trick_proto_swap            = true;
    state->trick_proto_swap_tcp_number = 143;

    sbuf_t  *buf          = makeTcpPacket(env, 96);
    uint32_t original_len = sbufGetLength(buf);
    uint8_t  original_payload[56];
    memoryCopy(original_payload,
               (const uint8_t *) sbufGetRawPtr(buf) + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr),
               sizeof(original_payload));

    lineSetRecalculateChecksum(env->line, true);
    ipmanipulatorEmitUpstream(t, env->line, buf, tunnelNextUpStreamPayload);

    require(captured_count == 1, "egress did not forward exactly one packet");
    sbuf_t              *wire    = captured[0];
    const struct ip_hdr *wire_ip = (const struct ip_hdr *) sbufGetRawPtr(wire);
    require(IPH_PROTO(wire_ip) == 143, "egress did not apply protocol swap last");
    require(sbufGetLength(wire) == original_len + 4U, "portghost trailer was not applied exactly once");
    require(! lineGetRecalculateChecksum(env->line), "swapped packet left a device checksum request pending");
    requireValidIpv4HeaderChecksum(wire);
    requireTcpChecksumMatchesRealProtocol(wire);

    captured[0]    = NULL;
    captured_count = 0;
    ipmanipulatorDownStreamPayload(t, env->line, wire);

    require(captured_count == 1, "downstream round trip did not forward exactly one packet");
    sbuf_t               *restored    = captured[0];
    const struct ip_hdr  *restored_ip = (const struct ip_hdr *) sbufGetRawPtr(restored);
    const struct tcp_hdr *restored_tcp =
        (const struct tcp_hdr *) ((const uint8_t *) sbufGetRawPtr(restored) + sizeof(struct ip_hdr));

    require(IPH_PROTO(restored_ip) == IPPROTO_TCP, "downstream did not restore TCP before parsing");
    require(sbufGetLength(restored) == original_len, "downstream did not remove the portghost trailer");
    require(lwip_ntohs(restored_tcp->src) == 12345 && lwip_ntohs(restored_tcp->dest) == 443,
            "downstream did not restore the original TCP tuple");
    require(memoryEqual((const uint8_t *) sbufGetRawPtr(restored) + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr),
                        original_payload,
                        sizeof(original_payload)),
            "egress/downstream round trip changed the TCP payload");
    require(lineGetRecalculateChecksum(env->line), "portghost restore did not request checksum recalculation");
    require(calcFullPacketChecksum(sbufGetMutablePtr(restored), sbufGetLength(restored)),
            "restored packet could not be checksummed as TCP");
    lineSetRecalculateChecksum(env->line, false);

    recycleCaptured(env);
    destroyTestTunnel(t);
}

static void testDownstreamResumeAfterSmuggleFinDoesNotRepeatRestoration(test_env_t *env)
{
    tunnel_t  next = {.fnPayloadU = capturePacket};
    tunnel_t  prev = {.fnPayloadD = capturePacket};
    tunnel_t *t    = createTestTunnel();
    t->next        = &next;
    t->prev        = &prev;

    ipmanipulator_tstate_t *state      = tunnelGetState(t);
    state->trick_source_port_ghost     = true;
    state->trick_dest_port_ghost       = true;
    state->trick_proto_swap            = true;
    state->trick_proto_swap_tcp_number = 143;

    sbuf_t  *buf          = makeTcpPacket(env, 96);
    uint32_t original_len = sbufGetLength(buf);
    uint8_t  original_payload[56];
    memoryCopy(original_payload,
               (const uint8_t *) sbufGetRawPtr(buf) + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr),
               sizeof(original_payload));

    lineSetRecalculateChecksum(env->line, true);
    ipmanipulatorEmitUpstream(t, env->line, buf, tunnelNextUpStreamPayload);
    require(captured_count == 1, "resume-stage fixture did not create one wire packet");

    sbuf_t *post_restore = captured[0];
    captured[0]          = NULL;
    captured_count       = 0;

    protoswaptrickDownStreamPayload(t, env->line, post_restore);
    require(portghosttrickRestore(t, env->line, &post_restore),
            "resume-stage fixture could not restore the portghost trailer");
    require(post_restore != NULL, "resume-stage fixture consumed a valid restored packet");
    ipmanipulatorDownStreamPayloadAfterSmuggleFin(t, env->line, post_restore);

    require(captured_count == 1, "post-smuggle-fin resume did not forward exactly one packet");

    sbuf_t               *restored    = captured[0];
    const struct ip_hdr  *restored_ip = (const struct ip_hdr *) sbufGetRawPtr(restored);
    const struct tcp_hdr *restored_tcp =
        (const struct tcp_hdr *) ((const uint8_t *) sbufGetRawPtr(restored) + sizeof(struct ip_hdr));

    require(IPH_PROTO(restored_ip) == IPPROTO_TCP, "post-smuggle-fin resume changed restored TCP protocol");
    require(sbufGetLength(restored) == original_len,
            "post-smuggle-fin resume removed or retained the portghost trailer twice");
    require(lwip_ntohs(restored_tcp->src) == 12345 && lwip_ntohs(restored_tcp->dest) == 443,
            "post-smuggle-fin resume changed the restored TCP tuple");
    require(memoryEqual((const uint8_t *) sbufGetRawPtr(restored) + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr),
                        original_payload,
                        sizeof(original_payload)),
            "post-smuggle-fin resume changed the restored payload");
    require(lineGetRecalculateChecksum(env->line), "post-smuggle-fin resume lost the portghost checksum request");
    require(calcFullPacketChecksum(sbufGetMutablePtr(restored), sbufGetLength(restored)),
            "post-smuggle-fin resumed packet could not be checksummed");
    lineSetRecalculateChecksum(env->line, false);

    recycleCaptured(env);
    destroyTestTunnel(t);
}

static void testAlreadyMappedEgressUnwraps(test_env_t *env)
{
    tunnel_t *t = createTestTunnel();

    ipmanipulator_tstate_t *state      = tunnelGetState(t);
    state->trick_proto_swap            = true;
    state->trick_proto_swap_tcp_number = 143;

    sbuf_t        *buf = makeTcpPacket(env, 96);
    struct ip_hdr *ip  = (struct ip_hdr *) sbufGetMutablePtr(buf);
    IPH_PROTO_SET(ip, 143);
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf)),
            "failed to checksum mapped-layer fixture");

    lineSetRecalculateChecksum(env->line, true);
    ipmanipulatorEmitUpstream(t, env->line, buf, capturePacket);

    require(captured_count == 1, "layered egress did not forward exactly one packet");
    const struct ip_hdr *wire_ip = (const struct ip_hdr *) sbufGetRawPtr(captured[0]);
    require(IPH_PROTO(wire_ip) == IPPROTO_TCP, "the upstream unwrapping layer re-mapped the packet");
    require(! lineGetRecalculateChecksum(env->line), "layered mapped packet left a checksum request pending");
    requireValidIpv4HeaderChecksum(captured[0]);
    requireTcpChecksumMatchesRealProtocol(captured[0]);

    recycleCaptured(env);
    destroyTestTunnel(t);
}

static void testTuplePreservingHelperEgress(test_env_t *env)
{
    tunnel_t *t = createTestTunnel();

    ipmanipulator_tstate_t *state      = tunnelGetState(t);
    state->trick_source_port_ghost     = true;
    state->trick_dest_port_ghost       = true;
    state->trick_proto_swap            = true;
    state->trick_proto_swap_tcp_number = 143;

    sbuf_t  *buf          = makeTcpPacket(env, 96);
    uint32_t original_len = sbufGetLength(buf);

    lineSetRecalculateChecksum(env->line, true);
    ipmanipulatorEmitUpstreamPreservingTuple(t, env->line, buf, capturePacket);

    require(captured_count == 1, "tuple-preserving egress did not forward exactly one packet");
    const struct ip_hdr  *wire_ip = (const struct ip_hdr *) sbufGetRawPtr(captured[0]);
    const struct tcp_hdr *wire_tcp =
        (const struct tcp_hdr *) ((const uint8_t *) sbufGetRawPtr(captured[0]) + sizeof(struct ip_hdr));
    require(IPH_PROTO(wire_ip) == 143, "tuple-preserving egress omitted protocol swap");
    require(sbufGetLength(captured[0]) == original_len, "tuple-preserving egress appended a portghost trailer");
    require(lwip_ntohs(wire_tcp->src) == 12345 && lwip_ntohs(wire_tcp->dest) == 443,
            "tuple-preserving egress changed the helper branch ports");
    require(! lineGetRecalculateChecksum(env->line), "tuple-preserving packet left a checksum request pending");
    requireValidIpv4HeaderChecksum(captured[0]);
    requireTcpChecksumMatchesRealProtocol(captured[0]);

    recycleCaptured(env);
    destroyTestTunnel(t);
}

static void runPortghostSegmentationCase(test_env_t *env, bool ghost_dest)
{
    tunnel_t               *t      = createTestTunnel();
    ipmanipulator_tstate_t *state  = tunnelGetState(t);
    state->trick_source_port_ghost = true;
    state->trick_dest_port_ghost   = ghost_dest;

    const uint16_t packet_len         = 213;
    const uint32_t headers_len        = sizeof(struct ip_hdr) + sizeof(struct tcp_hdr);
    const uint32_t source_payload_len = packet_len - headers_len;
    uint8_t        source_payload[packet_len - sizeof(struct ip_hdr) - sizeof(struct tcp_hdr)];
    sbuf_t        *buf       = makeTcpPacket(env, packet_len);
    struct ip_hdr *source_ip = (struct ip_hdr *) sbufGetMutablePtr(buf);
    IPH_OFFSET_SET(source_ip, lwip_htons(IP_RF | IP_DF));
    require(calcFullPacketChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf)),
            "failed to checksum the DF segmentation fixture");
    memoryCopy(source_payload, (const uint8_t *) sbufGetRawPtr(buf) + headers_len, source_payload_len);

    lineSetRecalculateChecksum(env->line, false);
    require(ipmanipulatorSendWithForwardMaybeSegmented(t, env->line, buf, capturePacket),
            "segmentation unexpectedly killed the packet line");
    require(captured_count > 1, "oversized packet was not segmented");

    uint8_t  reassembled[sizeof(source_payload)];
    uint32_t reassembled_len = 0;
    for (uint32_t i = 0; i < captured_count; ++i)
    {
        sbuf_t              *segment = captured[i];
        const struct ip_hdr *ip      = (const struct ip_hdr *) sbufGetRawPtr(segment);

        require(sbufGetLength(segment) <= GLOBAL_MTU_SIZE, "portghost segment exceeded GLOBAL_MTU_SIZE");
        require(lwip_ntohs(IPH_LEN(ip)) == sbufGetLength(segment),
                "segment IPv4 total length does not match its buffer");
        require((lwip_ntohs(IPH_OFFSET(ip)) & (IP_RF | IP_DF)) == (IP_RF | IP_DF),
                "TCP segmentation cleared a non-fragment IPv4 flag");
        require((lwip_ntohs(IPH_OFFSET(ip)) & (IP_MF | IP_OFFMASK)) == 0,
                "TCP segmentation retained IPv4 fragment state");
        require(portghosttrickRestore(t, env->line, &segment), "segment did not carry a restorable trailer");
        require(segment != NULL, "portghost restore consumed a valid segment");

        const struct tcp_hdr *tcp =
            (const struct tcp_hdr *) ((const uint8_t *) sbufGetRawPtr(segment) + sizeof(struct ip_hdr));
        require(lwip_ntohs(tcp->src) == 12345 && lwip_ntohs(tcp->dest) == 443,
                "segment restored to the wrong TCP tuple");

        uint32_t restored_payload_len = sbufGetLength(segment) - sizeof(struct ip_hdr) - sizeof(struct tcp_hdr);
        require(reassembled_len + restored_payload_len <= sizeof(reassembled), "reassembled payload overflow");
        memoryCopy(reassembled + reassembled_len,
                   (const uint8_t *) sbufGetRawPtr(segment) + headers_len,
                   restored_payload_len);
        reassembled_len += restored_payload_len;

        captured[i] = segment;
    }

    require(reassembled_len == source_payload_len, "restored segments have the wrong total payload length");
    require(memoryEqual(reassembled, source_payload, source_payload_len),
            "restored segment payloads do not reconstruct the source payload");

    recycleCaptured(env);
    lineSetRecalculateChecksum(env->line, false);
    destroyTestTunnel(t);
}

static void testPortghostSegmentation(test_env_t *env)
{
    uint16_t original_mtu = GLOBAL_MTU_SIZE;
    GLOBAL_MTU_SIZE       = 100;

    runPortghostSegmentationCase(env, false);
    runPortghostSegmentationCase(env, true);

    tunnel_t               *t      = createTestTunnel();
    ipmanipulator_tstate_t *state  = tunnelGetState(t);
    state->trick_source_port_ghost = true;
    state->trick_dest_port_ghost   = true;

    GLOBAL_MTU_SIZE = sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) + 4U;
    sbuf_t *buf     = makeTcpPacket(env, 80);
    require(ipmanipulatorSendWithForwardMaybeSegmented(t, env->line, buf, capturePacket),
            "header/trailer boundary unexpectedly killed the packet line");
    require(captured_count == 0, "header/trailer boundary did not bail before underflow");

    destroyTestTunnel(t);
    GLOBAL_MTU_SIZE = original_mtu;
}

static void testTrailerBoundaryAndExactFitGrowth(test_env_t *env)
{
    tunnel_t               *t         = createTestTunnel();
    ipmanipulator_tstate_t *state     = tunnelGetState(t);
    uint16_t                saved_mtu = GLOBAL_MTU_SIZE;

    state->trick_source_port_ghost = true;
    state->trick_dest_port_ghost   = true;

    GLOBAL_MTU_SIZE  = 100;
    sbuf_t *boundary = makeTcpPacket(env, 96);
    require(ipmanipulatorSendWithForwardMaybeSegmented(t, env->line, boundary, capturePacket),
            "prospective-MTU boundary unexpectedly killed the line");
    require(captured_count == 1 && sbufGetLength(captured[0]) == GLOBAL_MTU_SIZE,
            "prospective-MTU boundary was not emitted as one exact-MTU packet");
    recycleCaptured(env);

    sbuf_t  *exact_fit = sbufCreate(sizeof(struct ip_hdr) + sizeof(struct tcp_hdr));
    uint32_t exact_len = sbufGetMaximumWriteableSize(exact_fit);
    require(exact_len >= sizeof(struct ip_hdr) + sizeof(struct tcp_hdr) && exact_len <= UINT16_MAX - 4U,
            "exact-fit buffer fixture has an unusable capacity");
    sbuf_t *source = makeTcpPacket(env, (uint16_t) exact_len);
    sbufSetLength(exact_fit, exact_len);
    memoryCopy(sbufGetMutablePtr(exact_fit), sbufGetRawPtr(source), exact_len);
    lineReuseBuffer(env->line, source);

    uint32_t old_capacity = sbufGetMaximumWriteableSize(exact_fit);
    require(sbufGetLength(exact_fit) == old_capacity, "exact-fit fixture retained spare writable capacity");
    require(portghosttrickApply(t, env->line, &exact_fit), "exact-fit portghost append was rejected");
    require(exact_fit != NULL && sbufGetLength(exact_fit) == exact_len + 4U,
            "exact-fit portghost append did not grow by its trailer length");
    require(sbufGetMaximumWriteableSize(exact_fit) > old_capacity,
            "exact-fit portghost append did not reserve a larger buffer");
    require(portghosttrickRestore(t, env->line, &exact_fit), "exact-fit portghost packet was not restorable");
    require(exact_fit != NULL && sbufGetLength(exact_fit) == exact_len,
            "exact-fit portghost round trip changed the packet length");
    sbufDestroy(exact_fit);

    GLOBAL_MTU_SIZE = saved_mtu;
    destroyTestTunnel(t);
}

static void testPreservedFlagsAndPortghostSegmentTogether(test_env_t *env)
{
    tunnel_t  prev = {.fnPayloadD = capturePacket};
    tunnel_t *t    = createTestTunnel();
    t->prev        = &prev;

    ipmanipulator_tstate_t *state      = tunnelGetState(t);
    uint16_t                saved_mtu  = GLOBAL_MTU_SIZE;
    state->trick_source_port_ghost     = true;
    state->trick_dest_port_ghost       = true;
    state->trick_preserve_tcp_bitflags = true;
    state->trick_tcp_bit_changes       = true;
    state->up_tcp_bit_syn_action       = kDvsOff;

    GLOBAL_MTU_SIZE              = 100;
    const uint8_t original_flags = TCP_SYN | TCP_CWR | TCP_ECE | TCP_ACK | TCP_PSH | TCP_FIN;
    sbuf_t       *buf            = makeTcpPacket(env, 160);
    setTcpFlags(buf, original_flags);
    uint8_t source_payload[120];
    memoryCopy(source_payload,
               (const uint8_t *) sbufGetRawPtr(buf) + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr),
               sizeof(source_payload));

    tcpbitchangetrickUpStreamPayload(t, env->line, &buf);
    require(buf != NULL, "preserved-flags encoder consumed a segmentable packet");
    require(ipmanipulatorSendWithForwardMaybeSegmented(t, env->line, buf, capturePacket),
            "combined trailer segmentation unexpectedly killed the line");
    require(captured_count == 3, "combined flag/portghost trailers did not produce three segments");

    uint32_t expected_offsets[]    = {0, 55, 110};
    uint8_t  expected_live_flags[] = {
        TCP_CWR | TCP_ECE | TCP_ACK, TCP_ECE | TCP_ACK, TCP_ECE | TCP_ACK | TCP_PSH | TCP_FIN};
    uint8_t expected_original_flags[] = {
        TCP_SYN | TCP_CWR | TCP_ECE | TCP_ACK, TCP_ECE | TCP_ACK, TCP_ECE | TCP_ACK | TCP_PSH | TCP_FIN};

    for (uint32_t i = 0; i < captured_count; ++i)
    {
        const uint8_t        *packet = sbufGetRawPtr(captured[i]);
        const struct ip_hdr  *ip     = (const struct ip_hdr *) packet;
        const struct tcp_hdr *tcp    = (const struct tcp_hdr *) (packet + sizeof(struct ip_hdr));
        require(sbufGetLength(captured[i]) <= GLOBAL_MTU_SIZE, "combined trailer segment exceeded the MTU");
        require(lwip_ntohl(tcp->seqno) == 1000U + expected_offsets[i] + (i == 0 ? 0U : 1U),
                "combined trailer segment has discontinuous SYN-aware sequence space");
        require(getTcpFlags(tcp) == expected_live_flags[i], "live TCP flags were placed on the wrong segment");
        require(packet[lwip_ntohs(IPH_LEN(ip)) - 5U] == expected_original_flags[i],
                "original-flags metadata was not derived independently per segment");
    }

    sbuf_t *wire_segments[3];
    memoryCopy(wire_segments, captured, sizeof(wire_segments));
    memoryZero(captured, sizeof(captured));
    captured_count = 0;

    for (uint32_t i = 0; i < ARRAY_SIZE(wire_segments); ++i)
    {
        ipmanipulatorDownStreamPayload(t, env->line, wire_segments[i]);
    }

    require(captured_count == 3, "combined trailer segments were not independently restorable");
    uint8_t  reassembled[sizeof(source_payload)];
    uint32_t reassembled_len = 0;
    for (uint32_t i = 0; i < captured_count; ++i)
    {
        const uint8_t        *packet      = sbufGetRawPtr(captured[i]);
        const struct ip_hdr  *ip          = (const struct ip_hdr *) packet;
        const struct tcp_hdr *tcp         = (const struct tcp_hdr *) (packet + sizeof(struct ip_hdr));
        uint32_t              payload_len = lwip_ntohs(IPH_LEN(ip)) - sizeof(struct ip_hdr) - sizeof(struct tcp_hdr);

        require(getTcpFlags(tcp) == expected_original_flags[i],
                "restoration did not recover the segment's original TCP flags");
        memoryCopy(reassembled + reassembled_len, packet + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr), payload_len);
        reassembled_len += payload_len;
    }
    require(reassembled_len == sizeof(source_payload) &&
                memoryEqual(reassembled, source_payload, sizeof(source_payload)),
            "combined trailer restoration lost or treated payload as metadata");

    recycleCaptured(env);
    lineSetRecalculateChecksum(env->line, false);
    GLOBAL_MTU_SIZE = saved_mtu;
    destroyTestTunnel(t);
}

static void testUnsupportedOversizedPacketsDrop(test_env_t *env)
{
    tunnel_t                prev      = {.fnPayloadD = capturePacket};
    tunnel_t               *t         = createTestTunnel();
    ipmanipulator_tstate_t *state     = tunnelGetState(t);
    uint16_t                saved_mtu = GLOBAL_MTU_SIZE;
    t->prev                           = &prev;

    state->trick_source_port_ghost = true;
    state->trick_dest_port_ghost   = true;
    GLOBAL_MTU_SIZE                = 80;

    sbuf_t *rst = makeTcpPacket(env, 100);
    setTcpFlags(rst, TCP_RST | TCP_ACK);
    require(ipmanipulatorSendWithForwardMaybeSegmented(t, env->line, rst, capturePacket),
            "oversized RST drop unexpectedly killed the line");
    require(captured_count == 0, "oversized RST packet was partially emitted");

    sbuf_t *urg = makeTcpPacket(env, 100);
    setTcpFlags(urg, TCP_URG | TCP_ACK);
    require(ipmanipulatorSendWithForwardMaybeSegmented(t, env->line, urg, capturePacket),
            "oversized URG drop unexpectedly killed the line");
    require(captured_count == 0, "oversized URG packet was partially emitted");

    state->trick_preserve_tcp_bitflags = true;
    state->trick_tcp_bit_changes       = true;
    state->up_tcp_bit_rst_action       = kDvsOff;

    rst = makeTcpPacket(env, 100);
    setTcpFlags(rst, TCP_RST | TCP_ACK);
    tcpbitchangetrickUpStreamPayload(t, env->line, &rst);
    require(rst != NULL, "preserved RST fixture was consumed before final egress");
    require(ipmanipulatorSendWithForwardMaybeSegmented(t, env->line, rst, capturePacket),
            "preserved-original RST drop unexpectedly killed the line");
    require(captured_count == 0, "preserved-original RST evaded segmentation rejection");

    state->up_tcp_bit_rst_action = kDvsNoAction;
    state->up_tcp_bit_urg_action = kDvsOff;

    urg = makeTcpPacket(env, 100);
    setTcpFlags(urg, TCP_URG | TCP_ACK);
    tcpbitchangetrickUpStreamPayload(t, env->line, &urg);
    require(urg != NULL, "preserved URG fixture was consumed before final egress");
    require(ipmanipulatorSendWithForwardMaybeSegmented(t, env->line, urg, capturePacket),
            "preserved-original URG drop unexpectedly killed the line");
    require(captured_count == 0, "preserved-original URG evaded segmentation rejection");

    state->up_tcp_bit_urg_action   = kDvsNoAction;
    state->down_tcp_bit_rst_action = kDvsOff;

    rst = makeTcpPacket(env, 100);
    setTcpFlags(rst, TCP_RST | TCP_ACK);
    tcpbitchangetrickDownStreamPayload(t, env->line, &rst);
    require(rst != NULL, "downstream preserved RST fixture was consumed before final egress");
    ipmanipulatorSendDownstreamFinal(t, env->line, rst);
    require(captured_count == 0, "downstream preserved-original RST evaded segmentation rejection");

    state->down_tcp_bit_rst_action = kDvsNoAction;
    state->down_tcp_bit_urg_action = kDvsOff;

    urg = makeTcpPacket(env, 100);
    setTcpFlags(urg, TCP_URG | TCP_ACK);
    tcpbitchangetrickDownStreamPayload(t, env->line, &urg);
    require(urg != NULL, "downstream preserved URG fixture was consumed before final egress");
    ipmanipulatorSendDownstreamFinal(t, env->line, urg);
    require(captured_count == 0, "downstream preserved-original URG evaded segmentation rejection");

    state->trick_preserve_tcp_bitflags = false;
    state->trick_tcp_bit_changes       = false;
    state->down_tcp_bit_urg_action     = kDvsNoAction;

    sbuf_t *udp = makeUdpPacket(env, 77);
    require(ipmanipulatorSendWithForwardMaybeSegmented(t, env->line, udp, capturePacket),
            "oversized UDP drop unexpectedly killed the line");
    require(captured_count == 0, "oversized UDP packet was emitted instead of dropped");

    GLOBAL_MTU_SIZE = saved_mtu;
    destroyTestTunnel(t);
}

static void testDownstreamEncoderAndPostSegmentationDuplication(test_env_t *env)
{
    tunnel_t  prev = {.fnPayloadD = capturePacket};
    tunnel_t  next = {.fnPayloadU = capturePacket};
    tunnel_t *t    = createTestTunnel();
    t->prev        = &prev;
    t->next        = &next;

    ipmanipulator_tstate_t *state      = tunnelGetState(t);
    uint16_t                saved_mtu  = GLOBAL_MTU_SIZE;
    state->trick_preserve_tcp_bitflags = true;
    state->down_tcp_bit_syn_action     = kDvsOff;
    GLOBAL_MTU_SIZE                    = 80;

    sbuf_t *downstream = makeTcpPacket(env, 120);
    setTcpFlags(downstream, TCP_SYN | TCP_ACK | TCP_PSH);
    struct ip_hdr *downstream_ip = (struct ip_hdr *) sbufGetMutablePtr(downstream);
    IPH_OFFSET_SET(downstream_ip, lwip_htons(IP_RF | IP_DF));
    require(calcFullPacketChecksum(sbufGetMutablePtr(downstream), sbufGetLength(downstream)),
            "failed to checksum downstream IPv4-flags fixture");
    tcpbitchangetrickDownStreamPayload(t, env->line, &downstream);
    require(downstream != NULL, "downstream preserved-flags encoder consumed its packet");
    ipmanipulatorSendDownstreamFinal(t, env->line, downstream);
    require(captured_count == 3, "downstream preserved-flags encoder did not use final segmentation");
    for (uint32_t i = 0; i < captured_count; ++i)
    {
        require(sbufGetLength(captured[i]) <= GLOBAL_MTU_SIZE, "downstream segment exceeded the MTU");
        const struct ip_hdr *segment_ip = (const struct ip_hdr *) sbufGetRawPtr(captured[i]);
        require((lwip_ntohs(IPH_OFFSET(segment_ip)) & (IP_RF | IP_DF)) == (IP_RF | IP_DF),
                "downstream segmentation cleared a non-fragment IPv4 flag");
        require((lwip_ntohs(IPH_OFFSET(segment_ip)) & (IP_MF | IP_OFFMASK)) == 0,
                "downstream segmentation retained IPv4 fragment state");
    }
    recycleCaptured(env);

    state->trick_preserve_tcp_bitflags  = false;
    state->down_tcp_bit_syn_action      = kDvsNoAction;
    state->trick_source_port_ghost      = true;
    state->trick_packet_duplicate       = true;
    state->trick_packet_duplicate_count = 2;
    GLOBAL_MTU_SIZE                     = 80;

    sbuf_t *upstream = makeTcpPacket(env, 120);
    ipmanipulatorSendUpstreamFinal(t, env->line, upstream);
    require(captured_count == 9, "packet duplication did not run after three-way segmentation");
    for (uint32_t group = 0; group < 3; ++group)
    {
        const struct ip_hdr  *ip0  = (const struct ip_hdr *) sbufGetRawPtr(captured[group * 3U]);
        const struct tcp_hdr *tcp0 = (const struct tcp_hdr *) ((const uint8_t *) ip0 + sizeof(struct ip_hdr));
        for (uint32_t copy = 1; copy < 3; ++copy)
        {
            const struct ip_hdr  *ip  = (const struct ip_hdr *) sbufGetRawPtr(captured[group * 3U + copy]);
            const struct tcp_hdr *tcp = (const struct tcp_hdr *) ((const uint8_t *) ip + sizeof(struct ip_hdr));
            require(lwip_ntohl(tcp->seqno) == lwip_ntohl(tcp0->seqno),
                    "post-segmentation duplicates crossed segment boundaries");
        }
    }
    recycleCaptured(env);

    GLOBAL_MTU_SIZE = saved_mtu;
    destroyTestTunnel(t);
}

static void testSegmentSendStopsWhenLineDies(test_env_t *env)
{
    tunnel_t               *t         = createTestTunnel();
    ipmanipulator_tstate_t *state     = tunnelGetState(t);
    uint16_t                saved_mtu = GLOBAL_MTU_SIZE;

    state->trick_source_port_ghost = true;
    GLOBAL_MTU_SIZE                = 80;

    sbuf_t *buf = makeTcpPacket(env, 180);
    require(! ipmanipulatorSendWithForwardMaybeSegmented(t, env->line, buf, captureFirstThenKillLine),
            "multi-segment send reported a line alive after its first callback killed it");
    require(captured_count == 1, "multi-segment send continued after the line died");

    env->line->alive = true;
    recycleCaptured(env);
    GLOBAL_MTU_SIZE = saved_mtu;
    destroyTestTunnel(t);
}

static void testSniBlenderBoundsAndProtocolSwap(test_env_t *env)
{
    tunnel_t  next = {.fnPayloadU = capturePacket};
    tunnel_t *t    = createTestTunnel();
    t->next        = &next;

    ipmanipulator_tstate_t *state          = tunnelGetState(t);
    state->trick_sni_blender_packets_count = 2;
    state->trick_proto_swap                = true;
    state->trick_proto_swap_tcp_number     = 143;

    sbuf_t *short_buf = sbufCreate(12);
    sbufSetLength(short_buf, 12);
    memoryZero(sbufGetMutablePtr(short_buf), 12);
    require(! sniblendertrickUpStreamPayload(t, env->line, short_buf), "short SNI Blender packet was accepted");
    sbufDestroy(short_buf);

    sbuf_t  *buf = makeTcpPacket(env, 800);
    uint8_t *tls = sbufGetMutablePtr(buf) + sizeof(struct ip_hdr) + sizeof(struct tcp_hdr);
    tls[0]       = 0x16;
    tls[1]       = 0x03;
    tls[2]       = 0x03;
    tls[5]       = 0x01;
    require(calcFullPacketChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf)),
            "failed to checksum oversized SNI Blender packet");

    require(sniblendertrickUpStreamPayload(t, env->line, buf), "oversized SNI Blender packet was not handled");
    require(captured_count == 2, "SNI Blender emitted the wrong fragment count");

    bool saw_heap_backed_fragment = false;
    for (uint32_t i = 0; i < captured_count; ++i)
    {
        const struct ip_hdr *ip = (const struct ip_hdr *) sbufGetRawPtr(captured[i]);
        require(lwip_ntohs(IPH_LEN(ip)) == sbufGetLength(captured[i]), "SNI Blender fragment length is inconsistent");
        require(IPH_PROTO(ip) == 143, "SNI Blender fragment bypassed the egress protocol swap");
        requireValidIpv4HeaderChecksum(captured[i]);
        saw_heap_backed_fragment |= sbufGetTotalCapacityNoPadding(captured[i]) > kTestLargeBuffer;
    }
    require(saw_heap_backed_fragment, "oversized SNI Blender fragment did not use a heap-backed buffer");

    recycleCaptured(env);
    destroyTestTunnel(t);
}

static void countInit(tunnel_t *t, line_t *l)
{
    discard l;

    for (uint32_t i = 0; i < ARRAY_SIZE(init_targets); ++i)
    {
        if (init_targets[i] == t)
        {
            init_counts[i] += 1;
            return;
        }
    }
    require(false, "unexpected Init target");
}

static void resetInitCounters(tunnel_t *normal, tunnel_t *helper1, tunnel_t *helper2)
{
    init_targets[0] = normal;
    init_targets[1] = helper1;
    init_targets[2] = helper2;
    memoryZero(init_counts, sizeof(init_counts));
}

static void testHelperInitDeduplication(test_env_t *env)
{
    tunnel_t  normal              = {.fnInitU = countInit};
    tunnel_t  helper1             = {.fnInitU = countInit};
    tunnel_t  helper2             = {.fnInitU = countInit};
    tunnel_t *t                   = createTestTunnel();
    t->next                       = &normal;
    ipmanipulator_tstate_t *state = tunnelGetState(t);

    resetInitCounters(&normal, &helper1, &helper2);
    state->trick_real_sni_upstream_tunnel = &helper1;
    state->trick_real_fin_upstream_tunnel = &helper2;
    ipmanipulatorUpStreamInit(t, env->line);
    require(init_counts[0] == 1 && init_counts[1] == 1 && init_counts[2] == 1,
            "distinct helper branches were not initialized once each");

    resetInitCounters(&normal, &helper1, &helper2);
    state->trick_real_sni_upstream_tunnel = &helper1;
    state->trick_real_fin_upstream_tunnel = &helper1;
    ipmanipulatorUpStreamInit(t, env->line);
    require(init_counts[0] == 1 && init_counts[1] == 1, "aliased helper branch received duplicate Init");

    resetInitCounters(&normal, &helper1, &helper2);
    state->trick_real_sni_upstream_tunnel = NULL;
    state->trick_real_fin_upstream_tunnel = NULL;
    ipmanipulatorUpStreamInit(t, env->line);
    require(init_counts[0] == 1 && init_counts[1] == 0 && init_counts[2] == 0,
            "empty helper configuration initialized a helper");

    destroyTestTunnel(t);
}

static tunnel_t *createFromSettings(const char *settings_text)
{
    cJSON *settings = cJSON_Parse(settings_text);
    require(settings != NULL, "failed to parse IpManipulator settings fixture");

    node_t    node = {.node_settings_json = settings};
    tunnel_t *t    = ipmanipulatorCreate(&node);
    cJSON_Delete(settings);
    return t;
}

static void testProtocolSwapConfigurationValidation(void)
{
    require(createFromSettings("{\"protoswap\":17}") == NULL,
            "legacy protocol swap accepted a literal UDP replacement");
    require(createFromSettings("{\"protoswap-tcp\":17}") == NULL,
            "TCP protocol swap accepted a literal UDP replacement");
    require(createFromSettings("{\"protoswap-tcp\":6}") == NULL,
            "TCP protocol swap accepted a literal TCP replacement");
    require(createFromSettings("{\"protoswap-udp\":6}") == NULL,
            "UDP protocol swap accepted a literal TCP replacement");
    require(createFromSettings("{\"protoswap-udp\":17}") == NULL,
            "UDP protocol swap accepted a literal UDP replacement");
    require(createFromSettings("{\"protoswap-tcp-2\":144}") == NULL,
            "removed secondary TCP protocol swap was accepted alone");
    require(createFromSettings("{\"protoswap-tcp\":143,\"protoswap-tcp-2\":144}") == NULL,
            "removed secondary TCP protocol swap was accepted with protoswap-tcp");
    require(createFromSettings("{\"source-port-ghost\":true,\"protoswap-tcp-2\":144}") == NULL,
            "removed secondary TCP protocol swap was accepted with another trick");
    require(createFromSettings("{\"protoswap-tcp\":17,\"protoswap-udp\":6}") == NULL,
            "cross-mapped TCP/UDP protocols were accepted");
    require(createFromSettings("{\"protoswap-tcp\":143,\"protoswap-udp\":143}") == NULL,
            "shared TCP/UDP replacement protocol was accepted");

    tunnel_t *valid = createFromSettings("{\"protoswap-tcp\":143,\"protoswap-udp\":144}");
    require(valid != NULL, "unambiguous TCP/UDP protocol mapping was rejected");
    ipmanipulatorDestroy(valid, wwLifecycleStartupRollback());

    tunnel_t *tcp_only = createFromSettings("{\"protoswap-tcp\":143}");
    require(tcp_only != NULL, "single-family TCP-to-custom-protocol mapping was rejected");
    ipmanipulatorDestroy(tcp_only, wwLifecycleStartupRollback());
}

int main(void)
{
    checkSumInit();
    testProtocolSwapConfigurationValidation();

    test_env_t env;
    envSetup(&env);
    testEgressOrderAndDownstreamRoundTrip(&env);
    testDownstreamResumeAfterSmuggleFinDoesNotRepeatRestoration(&env);
    testAlreadyMappedEgressUnwraps(&env);
    testTuplePreservingHelperEgress(&env);
    testPortghostSegmentation(&env);
    testTrailerBoundaryAndExactFitGrowth(&env);
    testPreservedFlagsAndPortghostSegmentTogether(&env);
    testUnsupportedOversizedPacketsDrop(&env);
    testDownstreamEncoderAndPostSegmentationDuplication(&env);
    testSegmentSendStopsWhenLineDies(&env);
    testSniBlenderBoundsAndProtocolSwap(&env);
    testHelperInitDeduplication(&env);
    envTeardown(&env);
    return 0;
}
