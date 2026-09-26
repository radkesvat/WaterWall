#include "devices/tun/tun_linux_offload.h"

#include "wchecksum.h"

#include <linux/virtio_net.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum
{
    kIpv4BaseHeader = 20,
    kTcpBaseHeader  = 20,
    kTcpFin         = 0x01,
    kTcpPsh         = 0x08,
    kTcpAck         = 0x10,
    kTcpEce         = 0x40,
    kTcpCwr         = 0x80
};

static const uint8_t  kSource[4]      = {198, 51, 100, 10};
static const uint8_t  kDestination[4] = {203, 0, 113, 20};
static const uint32_t kFirstSequence  = UINT32_C(0xfffffffd);
static uint8_t        packet[UINT16_MAX + 1U];
static uint8_t        segment[2048];

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "tun_linux_offload_test: %s\n", message);
        exit(1);
    }
}

static uint16_t readBe16(const uint8_t *bytes)
{
    return (uint16_t) (((uint16_t) bytes[0] << 8U) | bytes[1]);
}

static uint32_t readBe32(const uint8_t *bytes)
{
    return ((uint32_t) bytes[0] << 24U) | ((uint32_t) bytes[1] << 16U) | ((uint32_t) bytes[2] << 8U) | bytes[3];
}

static void putBe16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t) (value >> 8U);
    bytes[1] = (uint8_t) value;
}

static void putBe32(uint8_t *bytes, uint32_t value)
{
    bytes[0] = (uint8_t) (value >> 24U);
    bytes[1] = (uint8_t) (value >> 16U);
    bytes[2] = (uint8_t) (value >> 8U);
    bytes[3] = (uint8_t) value;
}

static void putLe16(uint8_t *bytes, uint16_t value)
{
    bytes[0] = (uint8_t) value;
    bytes[1] = (uint8_t) (value >> 8U);
}

/* Independent byte-order scalar Internet checksum oracle. */
static uint16_t foldSum(uint64_t sum)
{
    while (sum >> 16U)
    {
        sum = (sum & UINT16_MAX) + (sum >> 16U);
    }
    return (uint16_t) sum;
}

static uint16_t oracleChecksum(const uint8_t *bytes, size_t length, uint64_t seed, size_t zero_field)
{
    uint64_t sum = seed;
    for (size_t i = 0; i < length; i += 2U)
    {
        const bool    zero_first  = zero_field != SIZE_MAX && (i == zero_field || i == zero_field + 1U);
        const bool    zero_second = zero_field != SIZE_MAX && (i + 1U == zero_field || i + 1U == zero_field + 1U);
        const uint8_t first       = zero_first ? 0 : bytes[i];
        const uint8_t second      = i + 1U >= length || zero_second ? 0 : bytes[i + 1U];
        sum += ((uint16_t) first << 8U) | second;
    }
    return (uint16_t) ~foldSum(sum);
}

static uint64_t tcpPseudoSum(const uint8_t *ip, const uint8_t destination[4], uint16_t tcp_length)
{
    return (uint64_t) readBe16(ip + 12) + readBe16(ip + 14) + readBe16(destination) + readBe16(destination + 2) + 6U +
           tcp_length;
}

static void verifyChecksums(const uint8_t *ip, uint32_t ip_header_length, uint32_t ip_length,
                            const uint8_t pseudo_destination[4])
{
    require(readBe16(ip + 10) == oracleChecksum(ip, ip_header_length, 0, 10), "incorrect IPv4 checksum");
    const uint16_t tcp_length = (uint16_t) (ip_length - ip_header_length);
    require(readBe16(ip + ip_header_length + 16) ==
                oracleChecksum(ip + ip_header_length, tcp_length, tcpPseudoSum(ip, pseudo_destination, tcp_length), 16),
            "incorrect TCP checksum");
}

static void metadata(uint8_t out[kTunVirtioHeaderSize], uint8_t flags, uint8_t gso_type, uint16_t hdr_len,
                     uint16_t gso_size, uint16_t checksum_start, uint16_t checksum_offset)
{
    memset(out, 0, kTunVirtioHeaderSize);
    out[0] = flags;
    out[1] = gso_type;
    putLe16(out + 2, hdr_len);
    putLe16(out + 4, gso_size);
    putLe16(out + 6, checksum_start);
    putLe16(out + 8, checksum_offset);
}

static uint32_t makeTcp(uint32_t payload_length, const uint8_t *ip_options, uint32_t ip_options_length,
                        const uint8_t *tcp_options, uint32_t tcp_options_length, uint8_t flags)
{
    require(ip_options_length % 4U == 0 && tcp_options_length % 4U == 0, "unaligned test options");
    require(ip_options_length <= 40 && tcp_options_length <= 40, "oversized test options");
    const uint32_t ip_header_length  = kIpv4BaseHeader + ip_options_length;
    const uint32_t tcp_header_length = kTcpBaseHeader + tcp_options_length;
    const uint32_t length            = ip_header_length + tcp_header_length + payload_length;
    require(length <= UINT16_MAX, "oversized test packet");

    memset(packet, 0, length);
    packet[0] = (uint8_t) (0x40U | ip_header_length / 4U);
    putBe16(packet + 2, (uint16_t) length);
    putBe16(packet + 4, UINT16_C(0xfffe));
    putBe16(packet + 6, UINT16_C(0x4000));
    packet[8] = 64;
    packet[9] = 6;
    memcpy(packet + 12, kSource, sizeof(kSource));
    memcpy(packet + 16, kDestination, sizeof(kDestination));
    if (ip_options_length != 0)
    {
        memcpy(packet + kIpv4BaseHeader, ip_options, ip_options_length);
    }

    uint8_t *tcp = packet + ip_header_length;
    putBe16(tcp, 40000);
    putBe16(tcp + 2, 443);
    putBe32(tcp + 4, kFirstSequence);
    putBe32(tcp + 8, UINT32_C(0x12345678));
    tcp[12] = (uint8_t) ((tcp_header_length / 4U) << 4U);
    tcp[13] = flags;
    putBe16(tcp + 14, 4096);
    if (tcp_options_length != 0)
    {
        memcpy(tcp + kTcpBaseHeader, tcp_options, tcp_options_length);
    }
    for (uint32_t i = 0; i < payload_length; ++i)
    {
        packet[ip_header_length + tcp_header_length + i] = (uint8_t) (i * 37U + 3U);
    }
    return length;
}

static void verifySegment(const tun_linux_offload_plan_t *plan, uint32_t offset, const uint8_t pseudo_destination[4],
                          uint8_t input_flags)
{
    uint32_t length = 0;
    require(tunLinuxOffloadPrepareSegment(packet, plan, offset, segment, sizeof(segment), &length),
            "segment preparation failed");
    const uint32_t payload_length =
        plan->payload_length - offset < plan->gso_size ? plan->payload_length - offset : plan->gso_size;
    require(length == plan->header_length + payload_length, "wrong segment length");
    require(readBe16(segment + 2) == length, "wrong segment IPv4 length");
    require(readBe16(segment + 4) == (uint16_t) (plan->ip_identification + offset / plan->gso_size),
            "wrong segment IPv4 ID");
    require(readBe32(segment + plan->ip_header_length + 4) == kFirstSequence + offset, "wrong TCP sequence");
    uint8_t expected_flags = input_flags;
    if (offset + payload_length < plan->payload_length)
    {
        expected_flags &= (uint8_t) ~(kTcpFin | kTcpPsh);
    }
    if (offset != 0)
    {
        expected_flags &= (uint8_t) ~kTcpCwr;
    }
    require(segment[plan->ip_header_length + 13] == expected_flags, "wrong segment TCP flags");
    require(memcmp(segment + plan->header_length, packet + plan->header_length + offset, payload_length) == 0,
            "segment payload did not cover input bytes exactly");
    require(memcmp(segment + 12, packet + 12, 8) == 0, "segment addresses changed");
    require(memcmp(segment + 20, packet + 20, plan->ip_header_length - 20U) == 0, "IPv4 options changed");
    require(memcmp(segment + plan->ip_header_length + 20,
                   packet + plan->ip_header_length + 20,
                   plan->header_length - plan->ip_header_length - 20U) == 0,
            "TCP options changed");
    const uint16_t tcp_length = (uint16_t) (length - plan->ip_header_length);
    uint64_t       expected_seed;
    if (plan->tcp_checksum_is_partial)
    {
        const uint16_t aggregate_tcp_length = (uint16_t) (plan->ip_length - plan->ip_header_length);
        expected_seed = (uint64_t) plan->tcp_checksum_seed + (uint16_t) ~aggregate_tcp_length + tcp_length;
    }
    else
    {
        expected_seed = tcpPseudoSum(segment, pseudo_destination, tcp_length);
    }
    require(readBe16(segment + plan->ip_header_length + 16) == foldSum(expected_seed),
            "prepared segment did not contain the folded TCP pseudoheader seed");
    require(readBe16(segment + 10) == oracleChecksum(segment, plan->ip_header_length, 0, 10),
            "IPv4 checksum was not completed during preparation");
    tunLinuxOffloadCompleteSegment(segment, length);
    verifyChecksums(segment, plan->ip_header_length, length, pseudo_destination);
}

static void testOrdinary(void)
{
    const uint32_t length = makeTcp(13, NULL, 0, NULL, 0, kTcpAck);
    uint8_t        before[128];
    memcpy(before, packet, length);
    uint8_t meta[kTunVirtioHeaderSize];
    metadata(meta, VIRTIO_NET_HDR_F_DATA_VALID, VIRTIO_NET_HDR_GSO_NONE, 0, 0, 0, 0);
    tun_linux_offload_plan_t plan = {0};
    require(tunLinuxOffloadPreflight(meta, packet, length, 1500, &plan) == kTunLinuxOffloadAccept &&
                plan.action == kTunLinuxOffloadOrdinary,
            "ordinary packet was rejected or changed action");
    require(memcmp(before, packet, length) == 0, "ordinary preflight changed bytes");

    metadata(meta, 0, VIRTIO_NET_HDR_GSO_NONE, 0, 0, 0, 0);
    require(tunLinuxOffloadPreflight(meta, packet, length, 1500, &plan) == kTunLinuxOffloadAccept &&
                plan.action == kTunLinuxOffloadOrdinary,
            "ordinary packet without DATA_VALID was rejected");
    require(memcmp(before, packet, length) == 0, "ordinary packet changed without NEEDS_CSUM");

    const uint8_t control_flags[] = {0x02, 0x04, kTcpAck | 0x20}; /* SYN, RST, and URG. */
    for (size_t i = 0; i < sizeof(control_flags); ++i)
    {
        const uint32_t control_length = makeTcp(0, NULL, 0, NULL, 0, control_flags[i]);
        if ((control_flags[i] & 0x20U) != 0)
        {
            putBe16(packet + 20 + 18, 1);
        }
        memcpy(before, packet, control_length);
        require(tunLinuxOffloadPreflight(meta, packet, control_length, 1500, &plan) == kTunLinuxOffloadAccept &&
                    plan.action == kTunLinuxOffloadOrdinary && memcmp(before, packet, control_length) == 0,
                "ordinary TCP control/urgent packet was filtered or changed");
    }

    static const uint8_t md5_option[20] = {19, 18, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 1, 1};
    const uint32_t       auth_length    = makeTcp(0, NULL, 0, md5_option, sizeof(md5_option), kTcpAck);
    memcpy(before, packet, auth_length);
    require(tunLinuxOffloadPreflight(meta, packet, auth_length, 1500, &plan) == kTunLinuxOffloadAccept &&
                plan.action == kTunLinuxOffloadOrdinary && memcmp(before, packet, auth_length) == 0,
            "ordinary authenticated TCP option was filtered or changed");

    memset(packet, 0, 28);
    packet[0] = 0x45;
    putBe16(packet + 2, 28);
    packet[8] = 64;
    packet[9] = 17;
    putBe16(packet + 20 + 4, 8);
    memcpy(before, packet, 28);
    require(tunLinuxOffloadPreflight(meta, packet, 28, 1500, &plan) == kTunLinuxOffloadAccept &&
                plan.action == kTunLinuxOffloadOrdinary && memcmp(before, packet, 28) == 0 &&
                readBe16(packet + 20 + 6) == 0,
            "ordinary UDP packet with disabled checksum changed");
}

static void testGenericChecksum(void)
{
    uint8_t                  meta[kTunVirtioHeaderSize];
    tun_linux_offload_plan_t plan = {0};
    memset(packet, 0, 33);
    packet[0] = 0x45;
    putBe16(packet + 2, 33);
    packet[8] = 64;
    packet[9] = 253;
    for (uint32_t i = 20; i < 33; ++i)
    {
        packet[i] = (uint8_t) (i * 11U);
    }
    putBe16(packet + 26, UINT16_C(0x1234));
    metadata(meta, VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_NONE, 0, 0, 21, 5);
    const uint16_t expected = oracleChecksum(packet + 21, 12, 0, SIZE_MAX);
    require(tunLinuxOffloadPreflight(meta, packet, 33, 1500, &plan) == kTunLinuxOffloadAccept &&
                plan.action == kTunLinuxOffloadChecksum,
            "generic NEEDS_CSUM was rejected");
    tunLinuxOffloadCompleteChecksum(packet, &plan);
    require(readBe16(packet + 26) == expected, "generic seeded checksum did not match independent oracle");

    memset(packet, 0, 24);
    packet[0] = 0x45;
    putBe16(packet + 2, 24);
    packet[8] = 64;
    packet[9] = 253;
    putBe16(packet + 20, UINT16_MAX);
    metadata(meta, VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_NONE, 0, 0, 20, 0);
    require(tunLinuxOffloadPreflight(meta, packet, 24, 1500, &plan) == kTunLinuxOffloadAccept,
            "zero-result checksum fixture was rejected");
    require(oracleChecksum(packet + 20, 4, 0, SIZE_MAX) == 0, "zero-result fixture is invalid");
    tunLinuxOffloadCompleteChecksum(packet, &plan);
    require(readBe16(packet + 20) == UINT16_MAX, "zero Internet checksum was not transmitted as all ones");
}

static void testOrdinaryIpv6(void)
{
    uint8_t                  meta[kTunVirtioHeaderSize];
    tun_linux_offload_plan_t plan = {0};
    uint8_t                  before[48];

    memset(packet, 0, sizeof(before));
    packet[0] = 0x60;
    putBe16(packet + 4, 8);
    packet[6]  = 58; /* ICMPv6 Router Solicitation. */
    packet[7]  = 255;
    packet[8]  = 0xfe;
    packet[9]  = 0x80;
    packet[23] = 1;
    packet[24] = 0xff;
    packet[25] = 2;
    packet[39] = 2;
    packet[40] = 133;
    memcpy(before, packet, sizeof(before));
    metadata(meta, VIRTIO_NET_HDR_F_DATA_VALID, VIRTIO_NET_HDR_GSO_NONE, 0, 0, 0, 0);
    require(tunLinuxOffloadPreflight(meta, packet, sizeof(before), 1500, &plan) == kTunLinuxOffloadAccept &&
                plan.action == kTunLinuxOffloadOrdinary && memcmp(before, packet, sizeof(before)) == 0,
            "ordinary IPv6 record was rejected or changed");

    packet[6] = 17; /* IPv6 UDP with kernel-provided partial checksum seed. */
    putBe16(packet + 40, 12345);
    putBe16(packet + 42, 53);
    putBe16(packet + 44, 8);
    putBe16(packet + 46, UINT16_C(0x1357));
    const uint16_t expected = oracleChecksum(packet + 40, 8, 0, SIZE_MAX);
    metadata(meta, VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_NONE, 0, 0, 40, 6);
    require(tunLinuxOffloadPreflight(meta, packet, sizeof(before), 1500, &plan) == kTunLinuxOffloadAccept &&
                plan.action == kTunLinuxOffloadChecksum,
            "ordinary IPv6 NEEDS_CSUM record was rejected");
    tunLinuxOffloadCompleteChecksum(packet, &plan);
    require(readBe16(packet + 46) == expected, "IPv6 deferred checksum did not match scalar oracle");
}

static void testMultiAndOneSegment(void)
{
    const uint8_t  flags  = kTcpAck | kTcpFin | kTcpPsh | kTcpCwr;
    const uint32_t length = makeTcp(17, NULL, 0, NULL, 0, flags);
    uint8_t        meta[kTunVirtioHeaderSize];
    metadata(meta, 0, VIRTIO_NET_HDR_GSO_TCPV4, 43, 6, 0, 0);
    tun_linux_offload_plan_t plan = {0};
    require(tunLinuxOffloadPreflight(meta, packet, length, 46, &plan) == kTunLinuxOffloadAccept &&
                plan.action == kTunLinuxOffloadSegment && plan.segment_count == 3,
            "multi-segment GSO preflight failed");
    verifySegment(&plan, 0, kDestination, flags);
    verifySegment(&plan, 6, kDestination, flags);
    verifySegment(&plan, 12, kDestination, flags);
    require(! tunLinuxOffloadPrepareSegment(packet, &plan, 1, segment, sizeof(segment), &(uint32_t) {0}),
            "unaligned segment offset accepted");
    require(! tunLinuxOffloadPrepareSegment(packet, &plan, 0, segment, 1, &(uint32_t) {0}),
            "undersized destination accepted");

    const uint8_t  ecn_flags  = kTcpAck | kTcpEce | kTcpCwr;
    const uint32_t ecn_length = makeTcp(12, NULL, 0, NULL, 0, ecn_flags);
    metadata(meta, 0, VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN, 40, 6, 0, 0);
    require(tunLinuxOffloadPreflight(meta, packet, ecn_length, 46, &plan) == kTunLinuxOffloadAccept &&
                plan.segment_count == 2,
            "Linux TCPv4 ECN GSO modifier was rejected");
    verifySegment(&plan, 0, kDestination, ecn_flags);
    verifySegment(&plan, 6, kDestination, ecn_flags);

    /* Linux MPTCP DSS MAP64 for 17 bytes, followed by an unknown length-4 option. */
    uint8_t tcp_options[24] = {30, 18, 0x20, 0x0c, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 17, 76, 4, 0xaa, 0xbb, 1, 1};
    const uint32_t option_length = makeTcp(17, NULL, 0, tcp_options, sizeof(tcp_options), flags);
    metadata(meta, 0, VIRTIO_NET_HDR_GSO_TCPV4, 64, 6, 0, 0);
    require(tunLinuxOffloadPreflight(meta, packet, option_length, 70, &plan) == kTunLinuxOffloadAccept &&
                plan.segment_count == 3,
            "MPTCP and unknown options were rejected in a multi-segment template");
    verifySegment(&plan, 0, kDestination, flags);
    verifySegment(&plan, 6, kDestination, flags);
    verifySegment(&plan, 12, kDestination, flags);

    tcp_options[17]           = 5;
    const uint32_t one_length = makeTcp(5, NULL, 0, tcp_options, sizeof(tcp_options), flags);
    metadata(meta, 0, VIRTIO_NET_HDR_GSO_TCPV4, 64, 10, 0, 0);
    require(tunLinuxOffloadPreflight(meta, packet, one_length, 69, &plan) == kTunLinuxOffloadAccept &&
                plan.segment_count == 1,
            "single segment with MPTCP and unknown option was rejected");
    verifySegment(&plan, 0, kDestination, flags);
}

static void testSourceRouteAndPartialSeed(void)
{
    static const uint8_t     route_option[8]      = {131, 7, 4, 203, 0, 113, 77, 0};
    static const uint8_t     final_destination[4] = {203, 0, 113, 77};
    const uint8_t            flags                = kTcpAck | kTcpPsh;
    const uint32_t           length               = makeTcp(12, route_option, sizeof(route_option), NULL, 0, flags);
    uint8_t                  meta[kTunVirtioHeaderSize];
    tun_linux_offload_plan_t plan = {0};

    const uint16_t whole_tcp_length = (uint16_t) (length - 28U);
    const uint16_t partial_seed     = foldSum(tcpPseudoSum(packet, final_destination, whole_tcp_length));
    putBe16(packet + 28 + 16, partial_seed);
    metadata(meta, VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_TCPV4, 48, 5, 28, 16);
    require(tunLinuxOffloadPreflight(meta, packet, length, 53, &plan) == kTunLinuxOffloadAccept &&
                plan.tcp_checksum_is_partial && plan.segment_count == 3,
            "source-route partial-seed GSO was rejected");
    verifySegment(&plan, 0, final_destination, flags);
    verifySegment(&plan, 5, final_destination, flags);
    verifySegment(&plan, 10, final_destination, flags);

    putBe16(packet + 28 + 16, 0);
    metadata(meta, 0, VIRTIO_NET_HDR_GSO_TCPV4, 48, 5, 0, 0);
    require(tunLinuxOffloadPreflight(meta, packet, length, 53, &plan) == kTunLinuxOffloadAccept &&
                ! plan.tcp_checksum_is_partial,
            "source-route fully checksummed GSO was rejected");
    verifySegment(&plan, 0, final_destination, flags);
}

static void testZeroTcpChecksum(void)
{
    const uint32_t length     = makeTcp(2, NULL, 0, NULL, 0, kTcpAck);
    const uint16_t tcp_length = (uint16_t) (length - kIpv4BaseHeader);
    putBe16(packet + 40, 0);
    putBe16(packet + 40,
            oracleChecksum(packet + kIpv4BaseHeader, tcp_length, tcpPseudoSum(packet, kDestination, tcp_length), 16));
    require(oracleChecksum(packet + kIpv4BaseHeader, tcp_length, tcpPseudoSum(packet, kDestination, tcp_length), 16) ==
                0,
            "zero TCP checksum fixture is invalid");

    uint8_t                  meta[kTunVirtioHeaderSize];
    tun_linux_offload_plan_t plan = {0};
    metadata(meta, 0, VIRTIO_NET_HDR_GSO_TCPV4, 40, 2, 0, 0);
    require(tunLinuxOffloadPreflight(meta, packet, length, 42, &plan) == kTunLinuxOffloadAccept &&
                plan.segment_count == 1,
            "zero TCP checksum segment was rejected");
    verifySegment(&plan, 0, kDestination, kTcpAck);
    require(readBe16(segment + kIpv4BaseHeader + 16) == 0, "valid zero TCP checksum was mangled");
}

static void testDetachedCompletion(void)
{
    const uint32_t length = makeTcp(7, NULL, 0, NULL, 0, kTcpAck);
    uint8_t        meta[kTunVirtioHeaderSize];
    metadata(meta, 0, VIRTIO_NET_HDR_GSO_TCPV4, 40, 7, 0, 0);
    tun_linux_offload_plan_t plan = {0};
    require(tunLinuxOffloadPreflight(meta, packet, length, 47, &plan) == kTunLinuxOffloadAccept,
            "detached-completion preflight failed");
    uint32_t segment_length = 0;
    require(tunLinuxOffloadPrepareSegment(packet, &plan, 0, segment, sizeof(segment), &segment_length),
            "detached-completion preparation failed");
    const uint16_t tcp_length = (uint16_t) (segment_length - kIpv4BaseHeader);
    require(oracleChecksum(
                segment + kIpv4BaseHeader, tcp_length, tcpPseudoSum(segment, kDestination, tcp_length), SIZE_MAX) != 0,
            "prepared TCP segment was already checksummed");
    memset(packet, 0, length);
    memset(&plan, 0, sizeof(plan));
    tunLinuxOffloadCompleteSegment(segment, segment_length);
    verifyChecksums(segment, kIpv4BaseHeader, segment_length, kDestination);
}

static void testLargeExpansion(void)
{
    const uint32_t length = makeTcp(1000, NULL, 0, NULL, 0, kTcpAck);
    uint8_t        meta[kTunVirtioHeaderSize];
    metadata(meta, 0, VIRTIO_NET_HDR_GSO_TCPV4, 40, 1, 0, 0);
    tun_linux_offload_plan_t plan = {0};
    require(tunLinuxOffloadPreflight(meta, packet, length, 1500, &plan) == kTunLinuxOffloadAccept &&
                plan.segment_count == 1000,
            "small-MSS expansion was capped or miscounted");
    uint32_t covered = 0;
    for (uint32_t offset = 0; offset < plan.payload_length; offset += plan.gso_size)
    {
        verifySegment(&plan, offset, kDestination, kTcpAck);
        covered += plan.gso_size;
    }
    require(covered == plan.payload_length, "large expansion lost payload coverage");
}

static void expectReject(const uint8_t meta[kTunVirtioHeaderSize], uint32_t length, uint16_t mtu,
                         tun_linux_offload_reject_t expected, const char *message)
{
    tun_linux_offload_plan_t plan = {0};
    require(tunLinuxOffloadPreflight(meta, packet, length, mtu, &plan) == expected, message);
}

static void testRejectedMetadataAndGeometry(void)
{
    const uint32_t length = makeTcp(12, NULL, 0, NULL, 0, kTcpAck);
    uint8_t        meta[kTunVirtioHeaderSize];
    metadata(meta, 0, VIRTIO_NET_HDR_GSO_TCPV4, 40, 6, 0, 0);
    expectReject(meta, UINT16_MAX + 1U, 1500, kTunLinuxOffloadOversized, "oversized representation accepted");
    expectReject(meta, 19, 1500, kTunLinuxOffloadMalformed, "short IPv4 record accepted");
    expectReject(meta, length + 1U, 1500, kTunLinuxOffloadMalformed, "trailing IP bytes accepted");
    meta[0] = 0x80;
    expectReject(meta, length, 1500, kTunLinuxOffloadUnsupported, "unnegotiated flag accepted");
    metadata(meta, 0, VIRTIO_NET_HDR_GSO_UDP, 40, 6, 0, 0);
    expectReject(meta, length, 1500, kTunLinuxOffloadUnsupported, "unnegotiated GSO type accepted");
    metadata(meta, 0, VIRTIO_NET_HDR_GSO_TCPV4, 40, 0, 0, 0);
    expectReject(meta, length, 1500, kTunLinuxOffloadMalformed, "zero GSO size accepted");
    metadata(meta, VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_TCPV4, 40, 6, 21, 16);
    expectReject(meta, length, 1500, kTunLinuxOffloadMalformed, "incorrect TCP checksum coordinates accepted");
    metadata(meta, 0, VIRTIO_NET_HDR_GSO_TCPV4, (uint16_t) (length + 1U), 6, 0, 0);
    expectReject(meta, length, 1500, kTunLinuxOffloadMalformed, "oversized metadata hdr_len accepted");
    metadata(meta, 0, VIRTIO_NET_HDR_GSO_TCPV4, 40, 6, 0, 0);
    expectReject(meta, length, 45, kTunLinuxOffloadOversized, "MTU-incompatible GSO record accepted");
    putBe16(packet + 6, UINT16_C(0x2000));
    expectReject(meta, length, 1500, kTunLinuxOffloadMalformed, "fragmented GSO record accepted");
    putBe16(packet + 6, UINT16_C(0x4000));
    packet[20 + 12] = 0x10;
    expectReject(meta, length, 1500, kTunLinuxOffloadMalformed, "invalid TCP data offset accepted");
    packet[20 + 12] = 0x50;
    packet[0]       = 0x65;
    expectReject(meta, length, 1500, kTunLinuxOffloadMalformed, "invalid IP version accepted");
    packet[0] = 0x44;
    expectReject(meta, length, 1500, kTunLinuxOffloadMalformed, "invalid IPv4 header length accepted");
    packet[0] = 0x45;
    putBe16(packet + 2, (uint16_t) (length - 1U));
    expectReject(meta, length, 1500, kTunLinuxOffloadMalformed, "inexact IPv4 total length accepted");
    putBe16(packet + 2, (uint16_t) length);
    metadata(meta, 0, VIRTIO_NET_HDR_GSO_NONE, 0, 0, 0, 0);
    expectReject(meta, length, 40, kTunLinuxOffloadOversized, "oversized ordinary record accepted");
    metadata(meta, VIRTIO_NET_HDR_F_NEEDS_CSUM, VIRTIO_NET_HDR_GSO_NONE, 0, 0, (uint16_t) length, 0);
    expectReject(meta, length, 1500, kTunLinuxOffloadMalformed, "out-of-range checksum start accepted");
}

int main(void)
{
    const uint8_t vector[] = {0x00, 0x01, 0x02};
    require(oracleChecksum(vector, sizeof(vector), 0, SIZE_MAX) == UINT16_C(0xfdfe),
            "checksum oracle self-check failed");
    checkSumInit();
    testOrdinary();
    testGenericChecksum();
    testOrdinaryIpv6();
    testMultiAndOneSegment();
    testSourceRouteAndPartialSeed();
    testZeroTcpChecksum();
    testDetachedCompletion();
    testLargeExpansion();
    testRejectedMetadataAndGeometry();
    puts("Linux TUN offload converter tests passed");
    return 0;
}
