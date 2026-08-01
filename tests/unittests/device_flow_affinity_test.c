#include "devices/device_flow_affinity.h"
#include "wwapi.h"

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

void deviceReaderSessionPost(device_reader_session_t *session, wid_t target_wid, sbuf_t **bufs, unsigned int count)
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

static void testIpv4SymmetryAndFragments(void)
{
    sbuf_t *forward = makeIpv4Packet(0x0A000001, 12345, 0xC0000201, 443, 6, 0);
    sbuf_t *reverse = makeIpv4Packet(0xC0000201, 443, 0x0A000001, 12345, 6, 0);
    require(affinityOf(forward) == affinityOf(reverse), "IPv4 TCP flow was not symmetric");

    sbuf_t *udp_forward = makeIpv4Packet(0x0A000002, 5353, 0xC6336401, 53, 17, 0);
    sbuf_t *udp_reverse = makeIpv4Packet(0xC6336401, 53, 0x0A000002, 5353, 17, 0);
    require(affinityOf(udp_forward) == affinityOf(udp_reverse), "IPv4 UDP flow was not symmetric");

    sbuf_t *first_fragment = makeIpv4Packet(0x0A000003, 1000, 0xCB007101, 2000, 6, 0x2000);
    sbuf_t *later_fragment = makeIpv4Packet(0x0A000003, 9999, 0xCB007101, 8888, 6, 185);
    PUT_BE16(sbufGetMutablePtr(first_fragment) + 4, 0xBEEF);
    PUT_BE16(sbufGetMutablePtr(later_fragment) + 4, 0xBEEF);
    require(affinityOf(first_fragment) == affinityOf(later_fragment),
            "first and later IPv4 fragments of one datagram selected different workers");

    sbuf_t *fragment_forward = makeIpv4Packet(0x0A000003, 1000, 0xCB007101, 2000, 6, 1);
    sbuf_t *fragment_reverse = makeIpv4Packet(0xCB007101, 9999, 0x0A000003, 8888, 6, 1);
    require(affinityOf(fragment_forward) == affinityOf(fragment_reverse),
            "non-initial IPv4 fragments incorrectly depended on payload bytes");

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

    sbuf_t *udp_forward = makeIpv6Packet(src, 5353, dst, 53, 17);
    sbuf_t *udp_reverse = makeIpv6Packet(dst, 53, src, 5353, 17);
    require(affinityOf(udp_forward) == affinityOf(udp_reverse), "IPv6 UDP flow was not symmetric");

    sbufDestroy(udp_reverse);
    sbufDestroy(udp_forward);
    sbufDestroy(tcp_reverse);
    sbufDestroy(tcp_forward);
}

static void testMalformedPacketsAndSingleWorker(void)
{
    uint8_t truncated_ipv4[19] = {0x45};
    uint8_t truncated_ipv6[39] = {0x60};
    uint8_t garbage[20]        = {0x10};
    wid_t   wid                = UINT8_MAX;

    require(! deviceFlowAffineWID(truncated_ipv4, sizeof(truncated_ipv4), &wid), "truncated IPv4 packet parsed");
    require(! deviceFlowAffineWID(truncated_ipv6, sizeof(truncated_ipv6), &wid), "truncated IPv6 packet parsed");
    require(! deviceFlowAffineWID(garbage, sizeof(garbage), &wid), "non-IP packet parsed");

    GSTATE.workers_count = 2;
    require(deviceFlowAffineWID(garbage, sizeof(garbage), &wid) && wid == 0,
            "single-worker fast path did not select worker zero");
    GSTATE.workers_count = 5;
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

    deviceFlowAffinityPostBatch((device_reader_session_t *) (uintptr_t) 1, packets, kPacketCount);

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
    testIpv4SymmetryAndFragments();
    testIpv6Symmetry();
    testMalformedPacketsAndSingleWorker();
    testBalancedDistribution();
    testBucketedDispatch();
    GSTATE.workers_count = 0;
    return 0;
}
