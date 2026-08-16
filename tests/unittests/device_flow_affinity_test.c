#include "devices/device_flow_affinity.h"
#include "worker_registry_fixture.h"
#include "wwapi.h"

#ifdef DEVICE_FLOW_AFFINITY_TEST_WIREGUARD
#include "WireGuardDevice/structure.h"
#endif

/*
 * Fake worker table for the stubbed GSTATE below. Without it the identity
 * predicates correctly report "not an event worker" and the checked
 * current-worker accessors reject this test.
 */
static test_worker_registry_t g_test_worker_registry;

enum
{
    kMaxCapturedPosts   = 256,
    kMaxCapturedBuffers = 64
};

typedef struct captured_post_s
{
    wid_t        wid;
    unsigned int count;
    sbuf_t      *bufs[kMaxCapturedBuffers];
} captured_post_t;

static captured_post_t captured_posts[kMaxCapturedPosts];
static unsigned int    captured_post_count;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

bool deviceReaderSessionPost(device_reader_session_t *session, wid_t target_wid, sbuf_t **bufs, unsigned int count)
{
    discard session;
    require(captured_post_count < kMaxCapturedPosts, "captured-post array overflow");
    require(count <= kMaxCapturedBuffers, "captured buffer bucket is too large");

    captured_post_t *post = &captured_posts[captured_post_count++];
    post->wid             = target_wid;
    post->count           = count;
    for (unsigned int i = 0; i < count; ++i)
    {
        post->bufs[i] = bufs[i];
    }
    return true;
}

bool deviceReaderSessionPostTracked(device_reader_session_t *session, wid_t target_wid, sbuf_t **bufs,
                                    const device_frag_affinity_publication_t *publications, unsigned int count)
{
    discard publications;
    return deviceReaderSessionPost(session, target_wid, bufs, count);
}

void deviceReaderSessionEnd(device_reader_session_t *session)
{
    discard session;
}

static sbuf_t *makeIpv4Packet(uint32_t src, uint16_t src_port, uint32_t dst, uint16_t dst_port, uint8_t proto,
                              uint16_t fragment_offset)
{
    uint32_t packet_len = 24;
    sbuf_t  *buf        = sbufCreate(packet_len);
    require(buf != NULL, "failed to allocate IPv4 packet");
    sbufSetLength(buf, packet_len);

    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, packet_len);
    packet[0] = 0x45;
    packet[9] = proto;
    // The declared total length is part of what makes a packet well formed, so a
    // fixture that left it zero would be feeding the hash malformed input.
    PUT_BE16(packet + 2, (uint16_t) packet_len);
    PUT_BE16(packet + 6, fragment_offset);
    PUT_BE32(packet + 12, src);
    PUT_BE32(packet + 16, dst);
    PUT_BE16(packet + 20, src_port);
    PUT_BE16(packet + 22, dst_port);
    return buf;
}

static sbuf_t *makeIpv6Packet(const uint8_t src[16], uint16_t src_port, const uint8_t dst[16], uint16_t dst_port,
                              uint8_t next_header)
{
    uint32_t packet_len = 44;
    sbuf_t  *buf        = sbufCreate(packet_len);
    require(buf != NULL, "failed to allocate IPv6 packet");
    sbufSetLength(buf, packet_len);

    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, packet_len);
    packet[0] = 0x60;
    packet[6] = next_header;
    PUT_BE16(packet + 4, (uint16_t) (packet_len - 40U));
    memoryCopy(packet + 8, src, 16);
    memoryCopy(packet + 24, dst, 16);
    PUT_BE16(packet + 40, src_port);
    PUT_BE16(packet + 42, dst_port);
    return buf;
}

static wid_t affinityOf(const sbuf_t *buf)
{
    wid_t wid = UINT8_MAX;
    require(deviceFlowAffineWID(sbufGetRawPtr(buf), sbufGetLength(buf), &wid), "expected parseable IP packet");
    return wid;
}

static uint64_t fullHashOf(const sbuf_t *buf)
{
    uint64_t hash = 0;
    require(deviceFlowAffinityHash(sbufGetRawPtr(buf), sbufGetLength(buf), &hash), "expected parseable IP packet");
    return hash;
}

/*
 * The worker index must be nothing more than the full hash reduced modulo the
 * worker count: line selection reads the same hash, so a second reduction path
 * would silently split the two decisions.
 */
static void requireWidIsHashModWorkers(const sbuf_t *buf, const char *message)
{
    require((uint64_t) affinityOf(buf) == fullHashOf(buf) % getWorkersCount(), message);
}

#ifdef DEVICE_FLOW_AFFINITY_TEST_WIREGUARD
static void requireWireGuardAffinityMatches(const sbuf_t *buf)
{
    wid_t expected = affinityOf(buf);

    for (wid_t current_wid = 0; current_wid < getWorkersCount(); ++current_wid)
    {
        wid_t target_wid = kInvalidWID;
        bool  should_hop =
            wireguarddeviceInnerPacketTargetWID(sbufGetRawPtr(buf), sbufGetLength(buf), current_wid, &target_wid);

        require(target_wid == expected, "WireGuard selected a different flow-affine worker");
        require(should_hop == (target_wid != current_wid), "WireGuard made the wrong same-worker decision");
    }
}

static void requireWireGuardKeepsMalformedHere(const uint8_t *packet, uint32_t length)
{
    wid_t target_wid = kInvalidWID;

    require(! wireguarddeviceInnerPacketTargetWID(packet, length, 2, &target_wid),
            "WireGuard tried to hop an unparseable inner packet");
    require(target_wid == 2, "WireGuard changed the worker for an unparseable inner packet");
}
#endif

static void testIpv4SymmetryAndFragments(void)
{
    sbuf_t *forward = makeIpv4Packet(0x0A000001, 12345, 0xC0000201, 443, 6, 0);
    sbuf_t *reverse = makeIpv4Packet(0xC0000201, 443, 0x0A000001, 12345, 6, 0);
    require(affinityOf(forward) == affinityOf(reverse), "IPv4 TCP flow was not symmetric");
    require(fullHashOf(forward) == fullHashOf(reverse), "IPv4 TCP full flow hash was not symmetric");

#ifdef DEVICE_FLOW_AFFINITY_TEST_WIREGUARD
    requireWireGuardAffinityMatches(forward);
    requireWireGuardAffinityMatches(reverse);
#endif

    sbuf_t *udp_forward = makeIpv4Packet(0x0A000002, 5353, 0xC6336401, 53, 17, 0);
    sbuf_t *udp_reverse = makeIpv4Packet(0xC6336401, 53, 0x0A000002, 5353, 17, 0);
    require(affinityOf(udp_forward) == affinityOf(udp_reverse), "IPv4 UDP flow was not symmetric");
    require(fullHashOf(udp_forward) == fullHashOf(udp_reverse), "IPv4 UDP full flow hash was not symmetric");

#ifdef DEVICE_FLOW_AFFINITY_TEST_WIREGUARD
    requireWireGuardAffinityMatches(udp_forward);
    requireWireGuardAffinityMatches(udp_reverse);
#endif

    sbuf_t *first_fragment = makeIpv4Packet(0x0A000003, 1000, 0xCB007101, 2000, 6, 0x2000);
    sbuf_t *later_fragment = makeIpv4Packet(0x0A000003, 9999, 0xCB007101, 8888, 6, 185);
    PUT_BE16(sbufGetMutablePtr(first_fragment) + 4, 0xBEEF);
    PUT_BE16(sbufGetMutablePtr(later_fragment) + 4, 0xBEEF);
    require(affinityOf(first_fragment) == affinityOf(later_fragment),
            "first and later IPv4 fragments of one datagram selected different workers");
    require(fullHashOf(first_fragment) == fullHashOf(later_fragment),
            "first and later IPv4 fragments of one datagram produced different full hashes");

#ifdef DEVICE_FLOW_AFFINITY_TEST_WIREGUARD
    requireWireGuardAffinityMatches(first_fragment);
    requireWireGuardAffinityMatches(later_fragment);
#endif

    sbuf_t *fragment_forward = makeIpv4Packet(0x0A000003, 1000, 0xCB007101, 2000, 6, 1);
    sbuf_t *fragment_reverse = makeIpv4Packet(0xCB007101, 9999, 0x0A000003, 8888, 6, 1);
    require(affinityOf(fragment_forward) == affinityOf(fragment_reverse),
            "non-initial IPv4 fragments incorrectly depended on payload bytes");
    require(fullHashOf(fragment_forward) == fullHashOf(fragment_reverse),
            "non-initial IPv4 fragment full hashes incorrectly depended on payload bytes");

#ifdef DEVICE_FLOW_AFFINITY_TEST_WIREGUARD
    requireWireGuardAffinityMatches(fragment_forward);
    requireWireGuardAffinityMatches(fragment_reverse);
#endif

    sbufDestroy(fragment_reverse);
    sbufDestroy(fragment_forward);
    sbufDestroy(later_fragment);
    sbufDestroy(first_fragment);
    sbufDestroy(udp_reverse);
    sbufDestroy(udp_forward);
    sbufDestroy(reverse);
    sbufDestroy(forward);
}

static void testIpv6Symmetry(void)
{
    static const uint8_t src[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6};
    static const uint8_t dst[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12};

    sbuf_t *tcp_forward = makeIpv6Packet(src, 23456, dst, 443, 6);
    sbuf_t *tcp_reverse = makeIpv6Packet(dst, 443, src, 23456, 6);
    require(affinityOf(tcp_forward) == affinityOf(tcp_reverse), "IPv6 TCP flow was not symmetric");
    require(fullHashOf(tcp_forward) == fullHashOf(tcp_reverse), "IPv6 TCP full flow hash was not symmetric");

#ifdef DEVICE_FLOW_AFFINITY_TEST_WIREGUARD
    requireWireGuardAffinityMatches(tcp_forward);
    requireWireGuardAffinityMatches(tcp_reverse);
#endif

    sbuf_t *udp_forward = makeIpv6Packet(src, 5353, dst, 53, 17);
    sbuf_t *udp_reverse = makeIpv6Packet(dst, 53, src, 5353, 17);
    require(affinityOf(udp_forward) == affinityOf(udp_reverse), "IPv6 UDP flow was not symmetric");
    require(fullHashOf(udp_forward) == fullHashOf(udp_reverse), "IPv6 UDP full flow hash was not symmetric");

#ifdef DEVICE_FLOW_AFFINITY_TEST_WIREGUARD
    requireWireGuardAffinityMatches(udp_forward);
    requireWireGuardAffinityMatches(udp_reverse);
#endif

    sbufDestroy(udp_reverse);
    sbufDestroy(udp_forward);
    sbufDestroy(tcp_reverse);
    sbufDestroy(tcp_forward);
}

static void testMalformedPacketsAndSingleWorker(void)
{
    uint8_t  truncated_ipv4[19] = {0x45};
    uint8_t  truncated_ipv6[39] = {0x60};
    uint8_t  garbage[20]        = {0x10};
    wid_t    wid                = UINT8_MAX;
    uint64_t hash               = UINT64_C(0xA5A5A5A5A5A5A5A5);

    require(! deviceFlowAffineWID(truncated_ipv4, sizeof(truncated_ipv4), &wid), "truncated IPv4 packet parsed");
    require(! deviceFlowAffineWID(truncated_ipv6, sizeof(truncated_ipv6), &wid), "truncated IPv6 packet parsed");
    require(! deviceFlowAffineWID(garbage, sizeof(garbage), &wid), "non-IP packet parsed");

    require(! deviceFlowAffinityHash(truncated_ipv4, sizeof(truncated_ipv4), &hash), "truncated IPv4 packet hashed");
    require(! deviceFlowAffinityHash(truncated_ipv6, sizeof(truncated_ipv6), &hash), "truncated IPv6 packet hashed");
    require(! deviceFlowAffinityHash(garbage, sizeof(garbage), &hash), "non-IP packet hashed");
    require(! deviceFlowAffinityHash(NULL, 40, &hash), "a NULL packet was hashed");
    require(hash == UINT64_C(0xA5A5A5A5A5A5A5A5), "a rejected packet modified the output hash");

#ifdef DEVICE_FLOW_AFFINITY_TEST_WIREGUARD
    requireWireGuardKeepsMalformedHere(truncated_ipv4, sizeof(truncated_ipv4));
    requireWireGuardKeepsMalformedHere(truncated_ipv6, sizeof(truncated_ipv6));
    requireWireGuardKeepsMalformedHere(garbage, sizeof(garbage));
#endif

    // One worker: a valid packet still selects worker zero, but a malformed one
    // is rejected rather than silently claimed, and the full hashes stay varied
    // so multi-line selection has something to work with.
    GSTATE.workers_count = 2;
    testWorkerRegistryInstall(&g_test_worker_registry);
    require(getWorkersCount() == 1, "the single-worker case did not publish exactly one worker");
    require(! deviceFlowAffineWID(garbage, sizeof(garbage), &wid),
            "a single worker must not bypass the malformed-packet contract");

    sbuf_t  *single_a      = makeIpv4Packet(0x0A000101, 1111, 0xC0000201, 443, 6, 0);
    sbuf_t  *single_b      = makeIpv4Packet(0x0A000102, 2222, 0xC0000201, 443, 6, 0);
    uint64_t single_hash_a = fullHashOf(single_a);
    uint64_t single_hash_b = fullHashOf(single_b);

    require(affinityOf(single_a) == 0 && affinityOf(single_b) == 0, "a single worker must select worker zero");
    require(single_hash_a != single_hash_b, "the single-worker path collapsed distinct flows to one hash");
    sbufDestroy(single_b);
    sbufDestroy(single_a);

    GSTATE.workers_count = 5;
    testWorkerRegistryInstall(&g_test_worker_registry);
}

/*
 * The declared length, not the buffer length, is what bounds a packet. A buffer
 * that is merely large enough is not proof of a well-formed packet, and reading
 * transport bytes from beyond the declared length would let unrelated trailing
 * bytes decide a flow's identity.
 */
static void testDeclaredLengthIsEnforced(void)
{
    uint64_t hash = UINT64_C(0x5A5A5A5A5A5A5A5A);

    // IPv4 total length of zero: what an unset fixture field looks like.
    sbuf_t *no_total_length = makeIpv4Packet(0x0A000001, 12345, 0xC0000201, 443, 6, 0);
    PUT_BE16(sbufGetMutablePtr(no_total_length) + 2, 0);
    require(! deviceFlowAffinityHash(sbufGetRawPtr(no_total_length), sbufGetLength(no_total_length), &hash),
            "an IPv4 packet declaring zero total length was hashed");

    // Shorter than its own header.
    sbuf_t *below_header = makeIpv4Packet(0x0A000001, 12345, 0xC0000201, 443, 6, 0);
    PUT_BE16(sbufGetMutablePtr(below_header) + 2, 19);
    require(! deviceFlowAffinityHash(sbufGetRawPtr(below_header), sbufGetLength(below_header), &hash),
            "an IPv4 packet declaring less than its header length was hashed");

    // Longer than the buffer that carries it.
    sbuf_t *truncated = makeIpv4Packet(0x0A000001, 12345, 0xC0000201, 443, 6, 0);
    PUT_BE16(sbufGetMutablePtr(truncated) + 2, 25);
    require(! deviceFlowAffinityHash(sbufGetRawPtr(truncated), sbufGetLength(truncated), &hash),
            "an IPv4 packet declaring more bytes than the buffer holds was hashed");

    require(hash == UINT64_C(0x5A5A5A5A5A5A5A5A), "a rejected packet modified the output hash");

    /*
     * A header-only packet followed by four trailing bytes that happen to look
     * like ports. Those bytes are outside the datagram, so they must not reach
     * the hash: two packets that differ only there are the same flow.
     */
    sbuf_t *trailing_a = makeIpv4Packet(0x0A000001, 12345, 0xC0000201, 443, 6, 0);
    sbuf_t *trailing_b = makeIpv4Packet(0x0A000001, 60000, 0xC0000201, 9999, 6, 0);
    PUT_BE16(sbufGetMutablePtr(trailing_a) + 2, 20);
    PUT_BE16(sbufGetMutablePtr(trailing_b) + 2, 20);
    require(fullHashOf(trailing_a) == fullHashOf(trailing_b),
            "bytes beyond the declared IPv4 total length changed the flow hash");

    // IPv6 payload length longer than the buffer.
    static const uint8_t src[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6};
    static const uint8_t dst[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12};

    sbuf_t *ipv6_truncated = makeIpv6Packet(src, 23456, dst, 443, 6);
    PUT_BE16(sbufGetMutablePtr(ipv6_truncated) + 4, 5);
    require(! deviceFlowAffinityHash(sbufGetRawPtr(ipv6_truncated), sbufGetLength(ipv6_truncated), &hash),
            "an IPv6 packet declaring more payload than the buffer holds was hashed");

    /*
     * A zero IPv6 payload length is the RFC 2675 jumbogram marker, and the real
     * size lives in a Hop-by-Hop Jumbo Payload option this parser does not walk.
     * It cannot be told apart from a malformed header, so both are rejected.
     */
    sbuf_t *zero_payload = makeIpv6Packet(src, 23456, dst, 443, 6);
    PUT_BE16(sbufGetMutablePtr(zero_payload) + 4, 0);
    require(! deviceFlowAffinityHash(sbufGetRawPtr(zero_payload), sbufGetLength(zero_payload), &hash),
            "an IPv6 packet declaring a zero payload length was hashed");

    // Not even with a Hop-by-Hop next header, which is what a real one carries.
    sbuf_t *hop_by_hop = makeIpv6Packet(src, 23456, dst, 443, 0);
    PUT_BE16(sbufGetMutablePtr(hop_by_hop) + 4, 0);
    require(! deviceFlowAffinityHash(sbufGetRawPtr(hop_by_hop), sbufGetLength(hop_by_hop), &hash),
            "an unvalidated IPv6 jumbogram was hashed");

    require(hash == UINT64_C(0x5A5A5A5A5A5A5A5A), "a rejected packet modified the output hash");

    // A payload too short to hold ports is still a well-formed packet.
    sbuf_t *short_payload_a = makeIpv6Packet(src, 23456, dst, 443, 6);
    sbuf_t *short_payload_b = makeIpv6Packet(src, 1, dst, 2, 6);
    PUT_BE16(sbufGetMutablePtr(short_payload_a) + 4, 3);
    PUT_BE16(sbufGetMutablePtr(short_payload_b) + 4, 3);
    require(fullHashOf(short_payload_a) == fullHashOf(short_payload_b),
            "bytes beyond a short IPv6 payload length changed the flow hash");

    sbufDestroy(short_payload_b);
    sbufDestroy(short_payload_a);
    sbufDestroy(hop_by_hop);
    sbufDestroy(zero_payload);
    sbufDestroy(ipv6_truncated);
    sbufDestroy(trailing_b);
    sbufDestroy(trailing_a);
    sbufDestroy(truncated);
    sbufDestroy(below_header);
    sbufDestroy(no_total_length);
}

/*
 * Protocols with no ports still need one stable, symmetric flow identity, which
 * is what keeps an ICMP error on the same worker as its peer's replies.
 */
static void testPortlessProtocolsAreStableAndSymmetric(void)
{
    // The port arguments are payload bytes here, not ports, so they must not matter.
    sbuf_t *icmp_forward = makeIpv4Packet(0x0A000001, 0x0800, 0xC0000201, 0x1234, 1, 0);
    sbuf_t *icmp_reverse = makeIpv4Packet(0xC0000201, 0x0000, 0x0A000001, 0x9999, 1, 0);

    require(fullHashOf(icmp_forward) == fullHashOf(icmp_reverse), "an ICMP exchange was not symmetric");
    require(affinityOf(icmp_forward) == affinityOf(icmp_reverse), "an ICMP exchange split across workers");

    // A different protocol between the same hosts is a different flow.
    sbuf_t *esp = makeIpv4Packet(0x0A000001, 0x0800, 0xC0000201, 0x1234, 50, 0);
    require(fullHashOf(esp) != fullHashOf(icmp_forward), "two protocols between one host pair collapsed to one flow");

    // A protocol that does carry ports must still use them.
    sbuf_t *tcp_a = makeIpv4Packet(0x0A000001, 1111, 0xC0000201, 443, 6, 0);
    sbuf_t *tcp_b = makeIpv4Packet(0x0A000001, 2222, 0xC0000201, 443, 6, 0);
    require(fullHashOf(tcp_a) != fullHashOf(tcp_b), "two TCP flows between one host pair collapsed to one flow");

    // SCTP is the third port-carrying protocol this parser reads.
    sbuf_t *sctp_forward = makeIpv4Packet(0x0A000004, 5000, 0xC0000204, 6000, 132, 0);
    sbuf_t *sctp_reverse = makeIpv4Packet(0xC0000204, 6000, 0x0A000004, 5000, 132, 0);
    sbuf_t *sctp_other   = makeIpv4Packet(0x0A000004, 5001, 0xC0000204, 6000, 132, 0);

    require(fullHashOf(sctp_forward) == fullHashOf(sctp_reverse), "an SCTP association was not symmetric");
    require(affinityOf(sctp_forward) == affinityOf(sctp_reverse), "an SCTP association split across workers");
    require(fullHashOf(sctp_forward) != fullHashOf(sctp_other), "two SCTP associations collapsed to one flow");

    // IPv6 without ports: the same address-pair-and-next-header identity.
    static const uint8_t v6_src[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6};
    static const uint8_t v6_dst[16] = {0x20, 0x01, 0x0D, 0xB8, 0, 7, 0, 8, 0, 9, 0, 10, 0, 11, 0, 12};

    // ICMPv6; the port arguments are payload bytes and must not matter.
    sbuf_t *icmpv6_forward = makeIpv6Packet(v6_src, 0x8000, v6_dst, 0x1234, 58);
    sbuf_t *icmpv6_reverse = makeIpv6Packet(v6_dst, 0x8100, v6_src, 0x9999, 58);
    sbuf_t *ipv6_esp       = makeIpv6Packet(v6_src, 0x8000, v6_dst, 0x1234, 50);

    require(fullHashOf(icmpv6_forward) == fullHashOf(icmpv6_reverse), "an ICMPv6 exchange was not symmetric");
    require(affinityOf(icmpv6_forward) == affinityOf(icmpv6_reverse), "an ICMPv6 exchange split across workers");
    require(fullHashOf(ipv6_esp) != fullHashOf(icmpv6_forward),
            "two IPv6 protocols between one host pair collapsed to one flow");

    sbufDestroy(ipv6_esp);
    sbufDestroy(icmpv6_reverse);
    sbufDestroy(icmpv6_forward);
    sbufDestroy(sctp_other);
    sbufDestroy(sctp_reverse);
    sbufDestroy(sctp_forward);
    sbufDestroy(tcp_b);
    sbufDestroy(tcp_a);
    sbufDestroy(esp);
    sbufDestroy(icmp_reverse);
    sbufDestroy(icmp_forward);
}

/*
 * The same packet must land on hash % workers for every configured worker count,
 * and its full hash must not depend on that count at all.
 */
static void testWidIsHashModuloWorkerCount(void)
{
    static const wid_t worker_counts[] = {1, 2, 4, 5};

    sbuf_t *tcp      = makeIpv4Packet(0x0A00000A, 40000, 0xC0A80001, 80, 6, 0);
    sbuf_t *udp      = makeIpv4Packet(0x0A00000B, 5353, 0xC6336401, 53, 17, 0);
    sbuf_t *fragment = makeIpv4Packet(0x0A00000C, 1000, 0xCB007101, 2000, 6, 0x2000);

    const uint64_t tcp_hash      = fullHashOf(tcp);
    const uint64_t udp_hash      = fullHashOf(udp);
    const uint64_t fragment_hash = fullHashOf(fragment);

    for (unsigned int i = 0; i < sizeof(worker_counts) / sizeof(worker_counts[0]); ++i)
    {
        GSTATE.workers_count = (uint32_t) worker_counts[i] + 1U;
        testWorkerRegistryInstall(&g_test_worker_registry);
        require(getWorkersCount() == worker_counts[i], "the fixture published the wrong worker count");

        requireWidIsHashModWorkers(tcp, "IPv4 TCP worker selection is not the full hash modulo the worker count");
        requireWidIsHashModWorkers(udp, "IPv4 UDP worker selection is not the full hash modulo the worker count");
        requireWidIsHashModWorkers(fragment,
                                   "IPv4 fragment worker selection is not the full hash modulo the worker count");

        require(fullHashOf(tcp) == tcp_hash && fullHashOf(udp) == udp_hash && fullHashOf(fragment) == fragment_hash,
                "the full flow hash changed with the worker count");
    }

    sbufDestroy(fragment);
    sbufDestroy(udp);
    sbufDestroy(tcp);

    GSTATE.workers_count = 5;
    testWorkerRegistryInstall(&g_test_worker_registry);
}

static void testBalancedDistribution(void)
{
    uint32_t counts[4] = {0};

    for (uint32_t flow = 0; flow < 4096; ++flow)
    {
        sbuf_t *buf = makeIpv4Packet(0x0A000001U + flow, (uint16_t) (1024U + flow), 0xCB007101, 443, 6, 0);
        counts[affinityOf(buf)]++;
        sbufDestroy(buf);
    }

    for (uint32_t wid = 0; wid < 4; ++wid)
    {
        require(counts[wid] > 800 && counts[wid] < 1250, "flow hash distribution is unexpectedly imbalanced");
    }
}

static void testBucketedDispatch(void)
{
    enum
    {
        kPacketCount = 17
    };

    sbuf_t *packets[kPacketCount];
    wid_t   expected[kPacketCount];
    bool    seen[kPacketCount];
    memoryZero(seen, sizeof(seen));
    memoryZero(captured_posts, sizeof(captured_posts));
    captured_post_count = 0;

    for (uint32_t i = 0; i < kPacketCount - 1; ++i)
    {
        packets[i]  = makeIpv4Packet(0x0A000001U + i, (uint16_t) (2000U + i), 0xC0000201, 443, 6, 0);
        expected[i] = affinityOf(packets[i]);
    }

    packets[kPacketCount - 1] = sbufCreate(8);
    sbufSetLength(packets[kPacketCount - 1], 8);
    memoryZero(sbufGetMutablePtr(packets[kPacketCount - 1]), 8);
    expected[kPacketCount - 1] = UINT8_MAX;

    // A real session object, because dispatch now reads its fragment-affinity
    // table. Leaving that table NULL keeps this case about bucketing alone;
    // device_frag_affinity_test.c is where the table itself is driven.
    device_reader_session_t session;
    memoryZero(&session, sizeof(session));
    session.batch_capacity = kMaxCapturedBuffers;

    deviceFlowAffinityPostBatch(&session, packets, kPacketCount);

    unsigned int delivered = 0;
    for (unsigned int pi = 0; pi < captured_post_count; ++pi)
    {
        captured_post_t *post = &captured_posts[pi];
        delivered += post->count;

        for (unsigned int bi = 0; bi < post->count; ++bi)
        {
            bool found = false;
            for (uint32_t source = 0; source < kPacketCount; ++source)
            {
                if (packets[source] != post->bufs[bi])
                {
                    continue;
                }

                require(! seen[source], "buffer was posted more than once");
                seen[source] = true;
                found        = true;
                if (expected[source] != UINT8_MAX)
                {
                    require(post->wid == expected[source], "buffer was posted to the wrong affinity bucket");
                }
                break;
            }
            require(found, "posted buffer did not belong to the source batch");
        }
    }

    require(delivered == kPacketCount, "not every buffer was posted");
    for (uint32_t i = 0; i < kPacketCount; ++i)
    {
        require(seen[i], "source buffer was not posted");
        sbufDestroy(packets[i]);
    }
}

int main(void)
{
    GSTATE.workers_count = 5;
    testWorkerRegistryInstall(&g_test_worker_registry);
    testIpv4SymmetryAndFragments();
    testIpv6Symmetry();
    testMalformedPacketsAndSingleWorker();
    testDeclaredLengthIsEnforced();
    testPortlessProtocolsAreStableAndSymmetric();
    testWidIsHashModuloWorkerCount();
    testBalancedDistribution();
    testBucketedDispatch();
    GSTATE.workers_count = 0;
    testWorkerRegistryRestore(&g_test_worker_registry);
    return 0;
}
