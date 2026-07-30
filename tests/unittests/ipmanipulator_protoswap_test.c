#include "IpManipulator/structure.h"
#include "tricks/protoswap/trick.h"
#include "wchecksum.h"
#include "wlibc.h"

#include <stdio.h>
#include <stdlib.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static tunnel_t *createTestTunnel(void)
{
    tunnel_t *t = memoryAllocateAlignedZero(sizeof(tunnel_t) + sizeof(ipmanipulator_tstate_t), kCpuLineCacheSize);
    require(t != NULL, "failed to allocate test tunnel");

    t->tstate_size                       = sizeof(ipmanipulator_tstate_t);
    ipmanipulator_tstate_t *state        = tunnelGetState(t);
    state->trick_proto_swap_tcp_number   = -1;
    state->trick_proto_swap_tcp_number_2 = -1;
    state->trick_proto_swap_udp_number   = -1;
    return t;
}

static void destroyTestTunnel(tunnel_t *t)
{
    memoryFreeAligned(t);
}

static ipmanipulator_tstate_t *testTunnelState(tunnel_t *t)
{
    return tunnelGetState(t);
}

static sbuf_t *createIpv4TcpPacket(uint16_t total_len, uint8_t ihl_words)
{
    uint16_t ip_hdr_len = (uint16_t) (ihl_words * 4U);
    require(total_len >= ip_hdr_len + sizeof(struct tcp_hdr), "packet too short for IP+TCP headers");

    sbuf_t *buf = sbufCreate(512);
    require(buf != NULL, "failed to allocate packet buffer");
    sbufSetLength(buf, total_len);

    uint8_t *raw = sbufGetMutablePtr(buf);
    memoryZero(raw, total_len);

    struct ip_hdr  *ipheader  = (struct ip_hdr *) raw;
    struct tcp_hdr *tcpheader = (struct tcp_hdr *) (raw + ip_hdr_len);

    IPH_VHL_SET(ipheader, 4, ihl_words);
    IPH_LEN_SET(ipheader, lwip_htons(total_len));
    IPH_TTL_SET(ipheader, 64);
    IPH_PROTO_SET(ipheader, IPPROTO_TCP);
    ipheader->src.addr  = PP_HTONL(LWIP_MAKEU32(10, 0, 0, 1));
    ipheader->dest.addr = PP_HTONL(LWIP_MAKEU32(10, 0, 0, 2));

    tcpheader->src  = lwip_htons(12345);
    tcpheader->dest = lwip_htons(80);
    TCPH_HDRLEN_FLAGS_SET(tcpheader, sizeof(struct tcp_hdr) / 4U, TCP_ACK);

    for (size_t i = ip_hdr_len + sizeof(struct tcp_hdr); i < total_len; ++i)
    {
        raw[i] = (uint8_t) (i + 1);
    }

    require(calcFullPacketChecksum(raw, total_len), "failed to compute initial TCP checksums");
    return buf;
}

static sbuf_t *createIpv4UdpPacket(uint16_t total_len)
{
    uint16_t ip_hdr_len = (uint16_t) sizeof(struct ip_hdr);
    require(total_len >= ip_hdr_len + sizeof(struct udp_hdr), "packet too short for IP+UDP headers");

    sbuf_t *buf = sbufCreate(512);
    require(buf != NULL, "failed to allocate packet buffer");
    sbufSetLength(buf, total_len);

    uint8_t *raw = sbufGetMutablePtr(buf);
    memoryZero(raw, total_len);

    struct ip_hdr  *ipheader  = (struct ip_hdr *) raw;
    struct udp_hdr *udpheader = (struct udp_hdr *) (raw + ip_hdr_len);

    IPH_VHL_SET(ipheader, 4, ip_hdr_len / 4U);
    IPH_LEN_SET(ipheader, lwip_htons(total_len));
    IPH_TTL_SET(ipheader, 64);
    IPH_PROTO_SET(ipheader, IPPROTO_UDP);
    ipheader->src.addr  = PP_HTONL(LWIP_MAKEU32(10, 0, 0, 1));
    ipheader->dest.addr = PP_HTONL(LWIP_MAKEU32(10, 0, 0, 2));

    udpheader->src  = lwip_htons(5000);
    udpheader->dest = lwip_htons(5001);
    udpheader->len  = lwip_htons((u16_t) (total_len - ip_hdr_len));

    for (size_t i = ip_hdr_len + sizeof(struct udp_hdr); i < total_len; ++i)
    {
        raw[i] = (uint8_t) (i + 10);
    }

    require(calcFullPacketChecksum(raw, total_len), "failed to compute initial UDP checksums");
    return buf;
}

static void testProtocolSwapTcpToCustomAndBack(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};

    state->trick_proto_swap_tcp_number = 143;

    sbuf_t  *buf    = createIpv4TcpPacket(60, 5);
    uint16_t len    = (uint16_t) sbufGetLength(buf);
    sbuf_t  *oracle = createIpv4TcpPacket(60, 5);

    /* Construct oracle for TCP -> 143 */
    struct ip_hdr *oracle_ip = (struct ip_hdr *) sbufGetMutablePtr(oracle);
    IPH_PROTO_SET(oracle_ip, 143);
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(oracle), len), "oracle IP calc failed");

    protoswaptrickUpStreamPayload(t, &line, buf);

    struct ip_hdr *buf_ip = (struct ip_hdr *) sbufGetMutablePtr(buf);
    require(IPH_PROTO(buf_ip) == 143, "protocol was not swapped to 143");
    require(! lineGetRecalculateChecksum(&line), "protocol swap modified recalculate_checksum flag");
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle), len), "swap result mismatch with oracle");

    /* Transport bytes must be 100% untouched */
    require(
        memoryEqual((const uint8_t *) sbufGetRawPtr(buf) + 20, (const uint8_t *) sbufGetRawPtr(oracle) + 20, len - 20),
        "transport bytes were modified");

    /* Now swap 143 back to TCP */
    sbuf_t *oracle_back = createIpv4TcpPacket(60, 5);
    protoswaptrickUpStreamPayload(t, &line, buf);

    require(IPH_PROTO(buf_ip) == IPPROTO_TCP, "protocol was not swapped back to TCP");
    require(! lineGetRecalculateChecksum(&line), "protocol swap back modified recalculate_checksum flag");
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle_back), len),
            "swap-back result mismatch with original oracle");

    sbufDestroy(buf);
    sbufDestroy(oracle);
    sbufDestroy(oracle_back);
    destroyTestTunnel(t);
}

static void testProtocolSwapUdpToCustomAndBack(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};

    state->trick_proto_swap_udp_number = 144;

    sbuf_t  *buf    = createIpv4UdpPacket(60);
    uint16_t len    = (uint16_t) sbufGetLength(buf);
    sbuf_t  *oracle = createIpv4UdpPacket(60);

    struct ip_hdr *oracle_ip = (struct ip_hdr *) sbufGetMutablePtr(oracle);
    IPH_PROTO_SET(oracle_ip, 144);
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(oracle), len), "oracle IP calc failed");

    protoswaptrickDownStreamPayload(t, &line, buf);

    struct ip_hdr *buf_ip = (struct ip_hdr *) sbufGetMutablePtr(buf);
    require(IPH_PROTO(buf_ip) == 144, "UDP protocol was not swapped to 144");
    require(! lineGetRecalculateChecksum(&line), "UDP protocol swap modified recalculate_checksum flag");
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle), len), "UDP swap result mismatch with oracle");

    /* Transport bytes must be 100% untouched */
    require(
        memoryEqual((const uint8_t *) sbufGetRawPtr(buf) + 20, (const uint8_t *) sbufGetRawPtr(oracle) + 20, len - 20),
        "UDP transport bytes were modified");

    /* Swap 144 back to UDP */
    sbuf_t *oracle_back = createIpv4UdpPacket(60);
    protoswaptrickDownStreamPayload(t, &line, buf);

    require(IPH_PROTO(buf_ip) == IPPROTO_UDP, "protocol was not swapped back to UDP");
    require(! lineGetRecalculateChecksum(&line), "UDP swap back modified recalculate_checksum flag");
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle_back), len),
            "UDP swap-back result mismatch with oracle");

    sbufDestroy(buf);
    sbufDestroy(oracle);
    sbufDestroy(oracle_back);
    destroyTestTunnel(t);
}

static void testProtocolSwapWithIpOptions(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};

    state->trick_proto_swap_tcp_number = 143;

    /* IHL = 6 -> 24-byte IP header including 4 bytes of options */
    sbuf_t  *buf    = createIpv4TcpPacket(64, 6);
    uint16_t len    = (uint16_t) sbufGetLength(buf);
    sbuf_t  *oracle = createIpv4TcpPacket(64, 6);

    struct ip_hdr *oracle_ip = (struct ip_hdr *) sbufGetMutablePtr(oracle);
    IPH_PROTO_SET(oracle_ip, 143);
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(oracle), len), "oracle IP calc with options failed");

    protoswaptrickUpStreamPayload(t, &line, buf);

    struct ip_hdr *buf_ip = (struct ip_hdr *) sbufGetMutablePtr(buf);
    require(IPH_PROTO(buf_ip) == 143, "protocol with IP options was not swapped");
    require(! lineGetRecalculateChecksum(&line), "protocol swap with IP options modified flag");
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle), len),
            "swap result with IP options mismatch with oracle");
    require(
        memoryEqual((const uint8_t *) sbufGetRawPtr(buf) + 24, (const uint8_t *) sbufGetRawPtr(oracle) + 24, len - 24),
        "transport bytes with IP options were modified");

    sbufDestroy(buf);
    sbufDestroy(oracle);
    destroyTestTunnel(t);
}

static void testProtocolSwapFragmentedPacket(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};

    state->trick_proto_swap_tcp_number = 143;

    sbuf_t        *buf    = createIpv4TcpPacket(60, 5);
    struct ip_hdr *buf_ip = (struct ip_hdr *) sbufGetMutablePtr(buf);
    IPH_OFFSET_SET(buf_ip, lwip_htons(IP_MF));
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(buf), 60), "fragment IP calc failed");

    sbuf_t        *oracle    = createIpv4TcpPacket(60, 5);
    struct ip_hdr *oracle_ip = (struct ip_hdr *) sbufGetMutablePtr(oracle);
    IPH_OFFSET_SET(oracle_ip, lwip_htons(IP_MF));
    IPH_PROTO_SET(oracle_ip, 143);
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(oracle), 60), "fragment oracle IP calc failed");

    protoswaptrickUpStreamPayload(t, &line, buf);

    require(IPH_PROTO(buf_ip) == 143, "fragmented packet protocol was not swapped");
    require(! lineGetRecalculateChecksum(&line), "fragmented packet swap modified flag");
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle), 60), "fragmented packet swap mismatch with oracle");

    sbufDestroy(buf);
    sbufDestroy(oracle);
    destroyTestTunnel(t);
}

static void testProtocolSwapSameProtocolAdvancesToggle(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};

    state->trick_proto_swap_tcp_number   = IPPROTO_TCP;
    state->trick_proto_swap_tcp_number_2 = 144;

    sbuf_t  *buf    = createIpv4TcpPacket(60, 5);
    uint16_t len    = (uint16_t) sbufGetLength(buf);
    sbuf_t  *before = sbufCreate(512);
    sbufSetLength(before, len);
    memoryCopy(sbufGetMutablePtr(before), sbufGetRawPtr(buf), len);

    /* First packet matches candidate IPPROTO_TCP -> toggle 0 -> returns true without byte changes */
    protoswaptrickUpStreamPayload(t, &line, buf);
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(before), len), "same-protocol packet bytes were modified");
    require(! lineGetRecalculateChecksum(&line), "same-protocol packet modified flag");

    /* Second packet -> toggle 1 -> swapped to 144 */
    protoswaptrickUpStreamPayload(t, &line, buf);
    struct ip_hdr *buf_ip = (struct ip_hdr *) sbufGetMutablePtr(buf);
    require(IPH_PROTO(buf_ip) == 144, "toggle 1 failed to swap to 144");

    sbufDestroy(buf);
    sbufDestroy(before);
    destroyTestTunnel(t);
}

static void testProtocolSwapMalformedHeader(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};

    state->trick_proto_swap_tcp_number   = 143;
    state->trick_proto_swap_tcp_number_2 = 144;

    /* 1. IHL < 5 (IHL = 4) */
    sbuf_t        *buf      = createIpv4TcpPacket(60, 5);
    struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);
    IPH_VHL_SET(ipheader, 4, 4);
    sbuf_t *before = sbufCreate(512);
    sbufSetLength(before, 60);
    memoryCopy(sbufGetMutablePtr(before), sbufGetRawPtr(buf), 60);

    protoswaptrickUpStreamPayload(t, &line, buf);
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(before), 60), "malformed IHL=4 packet was modified");
    require(! lineGetRecalculateChecksum(&line), "malformed IHL=4 packet modified flag");
    sbufDestroy(buf);

    /* 2. IHL > 15 (IHL = 16) */
    buf      = createIpv4TcpPacket(60, 5);
    ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);
    IPH_VHL_SET(ipheader, 4, 16);
    memoryCopy(sbufGetMutablePtr(before), sbufGetRawPtr(buf), 60);

    protoswaptrickUpStreamPayload(t, &line, buf);
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(before), 60), "malformed IHL=16 packet was modified");
    sbufDestroy(buf);

    /* 3. Total length < IHL */
    buf      = createIpv4TcpPacket(60, 5);
    ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);
    IPH_LEN_SET(ipheader, lwip_htons(10));
    memoryCopy(sbufGetMutablePtr(before), sbufGetRawPtr(buf), 60);

    protoswaptrickUpStreamPayload(t, &line, buf);
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(before), 60), "total_len < IHL packet was modified");
    sbufDestroy(buf);

    /* 4. Total length > sbuf length */
    buf      = createIpv4TcpPacket(60, 5);
    ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);
    IPH_LEN_SET(ipheader, lwip_htons(200));
    sbufSetLength(buf, 60);
    memoryCopy(sbufGetMutablePtr(before), sbufGetRawPtr(buf), 60);

    protoswaptrickUpStreamPayload(t, &line, buf);
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(before), 60), "total_len > sbuf length packet was modified");

    /* Verify toggle was NOT advanced by any of the 4 malformed packets */
    sbuf_t *valid = createIpv4TcpPacket(60, 5);
    protoswaptrickUpStreamPayload(t, &line, valid);
    require(IPH_PROTO((struct ip_hdr *) sbufGetMutablePtr(valid)) == 143,
            "toggle was incorrectly advanced by malformed packets");

    sbufDestroy(buf);
    sbufDestroy(before);
    sbufDestroy(valid);
    destroyTestTunnel(t);
}

static void testProtocolSwapTcpToUdpDirect(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};

    state->trick_proto_swap_tcp_number = IPPROTO_UDP;

    sbuf_t  *buf    = createIpv4TcpPacket(60, 5);
    uint16_t len    = (uint16_t) sbufGetLength(buf);
    sbuf_t  *oracle = createIpv4TcpPacket(60, 5);

    struct ip_hdr *oracle_ip = (struct ip_hdr *) sbufGetMutablePtr(oracle);
    IPH_PROTO_SET(oracle_ip, IPPROTO_UDP);
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(oracle), len), "oracle IP calc failed");

    protoswaptrickUpStreamPayload(t, &line, buf);

    struct ip_hdr *buf_ip = (struct ip_hdr *) sbufGetMutablePtr(buf);
    require(IPH_PROTO(buf_ip) == IPPROTO_UDP, "protocol was not swapped to UDP");
    require(! lineGetRecalculateChecksum(&line), "protocol swap modified recalculate_checksum flag");
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle), len), "TCP->UDP swap result mismatch with oracle");

    /* Original TCP header & checksum inside transport bytes must be unchanged */
    struct tcp_hdr *tcph = (struct tcp_hdr *) (sbufGetMutablePtr(buf) + 20);
    require(tcph->dest == lwip_htons(80), "TCP dest port was modified during swap");

    sbufDestroy(buf);
    sbufDestroy(oracle);
    destroyTestTunnel(t);
}

static void testProtocolSwapPreExistingFlagPreserved(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};

    lineSetRecalculateChecksum(&line, true);
    state->trick_proto_swap_tcp_number = 143;

    sbuf_t *buf = createIpv4TcpPacket(60, 5);
    protoswaptrickUpStreamPayload(t, &line, buf);

    require(lineGetRecalculateChecksum(&line), "pre-existing recalculate_checksum flag was cleared");
    struct ip_hdr *buf_ip = (struct ip_hdr *) sbufGetMutablePtr(buf);
    require(IPH_PROTO(buf_ip) == 143, "protocol was not swapped");

    sbufDestroy(buf);
    destroyTestTunnel(t);
}

static void testAlternatingTcpReplacements(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};

    state->trick_proto_swap_tcp_number   = 143;
    state->trick_proto_swap_tcp_number_2 = 144;

    /* Upstream packet 1 -> 143 */
    sbuf_t *buf1 = createIpv4TcpPacket(60, 5);
    protoswaptrickUpStreamPayload(t, &line, buf1);
    require(IPH_PROTO((struct ip_hdr *) sbufGetMutablePtr(buf1)) == 143, "upstream 1 failed to swap to 143");

    /* Upstream packet 2 -> 144 */
    sbuf_t *buf2 = createIpv4TcpPacket(60, 5);
    protoswaptrickUpStreamPayload(t, &line, buf2);
    require(IPH_PROTO((struct ip_hdr *) sbufGetMutablePtr(buf2)) == 144, "upstream 2 failed to swap to 144");

    /* Downstream has independent sequence -> 143 */
    sbuf_t *buf_d1 = createIpv4TcpPacket(60, 5);
    protoswaptrickDownStreamPayload(t, &line, buf_d1);
    require(IPH_PROTO((struct ip_hdr *) sbufGetMutablePtr(buf_d1)) == 143, "downstream 1 failed to swap to 143");

    /* Malformed packet rejected -> does NOT advance toggle */
    sbuf_t *malformed = sbufCreate(256);
    sbufSetLength(malformed, 10);
    memoryZero(sbufGetMutablePtr(malformed), 10);
    protoswaptrickUpStreamPayload(t, &line, malformed);

    /* Upstream packet 3 -> 143 (since toggle was at 0 after 143, 144) -> next is 143 */
    sbuf_t *buf3 = createIpv4TcpPacket(60, 5);
    protoswaptrickUpStreamPayload(t, &line, buf3);
    require(IPH_PROTO((struct ip_hdr *) sbufGetMutablePtr(buf3)) == 143, "upstream 3 failed to swap to 143");

    sbufDestroy(buf1);
    sbufDestroy(buf2);
    sbufDestroy(buf_d1);
    sbufDestroy(malformed);
    sbufDestroy(buf3);
    destroyTestTunnel(t);
}

static void testRejectionAndNoMatch(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};

    state->trick_proto_swap_tcp_number = 143;

    /* 1. IPv6 packet */
    sbuf_t *buf = sbufCreate(256);
    sbufSetLength(buf, 40);
    uint8_t *raw = sbufGetMutablePtr(buf);
    memoryZero(raw, 40);
    raw[0] = 0x60;
    uint8_t before[40];
    memoryCopy(before, raw, 40);

    protoswaptrickUpStreamPayload(t, &line, buf);
    require(memoryEqual(sbufGetRawPtr(buf), before, 40), "IPv6 packet was modified");
    require(! lineGetRecalculateChecksum(&line), "IPv6 packet modified flag");
    sbufDestroy(buf);

    /* 2. Unmatched protocol (UDP when only TCP swap configured) */
    buf                = createIpv4UdpPacket(60);
    sbuf_t *before_udp = sbufCreate(256);
    sbufSetLength(before_udp, 60);
    memoryCopy(sbufGetMutablePtr(before_udp), sbufGetRawPtr(buf), 60);

    protoswaptrickUpStreamPayload(t, &line, buf);
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(before_udp), 60), "unmatched UDP packet was modified");
    require(! lineGetRecalculateChecksum(&line), "unmatched UDP packet modified flag");

    sbufDestroy(buf);
    sbufDestroy(before_udp);
    destroyTestTunnel(t);
}

int main(void)
{
    checkSumInit();
    testProtocolSwapTcpToCustomAndBack();
    testProtocolSwapUdpToCustomAndBack();
    testProtocolSwapWithIpOptions();
    testProtocolSwapFragmentedPacket();
    testProtocolSwapSameProtocolAdvancesToggle();
    testProtocolSwapMalformedHeader();
    testProtocolSwapTcpToUdpDirect();
    testProtocolSwapPreExistingFlagPreserved();
    testAlternatingTcpReplacements();
    testRejectionAndNoMatch();
    return 0;
}
