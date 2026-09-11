#include "IpManipulator/structure.h"
#include "tricks/protoswap/trick.h"
#include "wchecksum.h"
#include "wlibc.h"

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

    t->tstate_size                     = sizeof(ipmanipulator_tstate_t);
    ipmanipulator_tstate_t *state      = tunnelGetState(t);
    state->trick_proto_swap_tcp_number = -1;
    state->trick_proto_swap_udp_number = -1;
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

static void normalizeOracle(sbuf_t *buf)
{
    struct ip_hdr *ip  = (struct ip_hdr *) sbufGetMutablePtr(buf);
    uint32_t       src = ip->src.addr, dst = ip->dest.addr;
    ip->src.addr = ip->dest.addr = 0;
    require(calcFullPacketChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf)), "oracle normalization failed");
    ip->src.addr  = src;
    ip->dest.addr = dst;
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
    normalizeOracle(oracle);
    IPH_PROTO_SET(oracle_ip, 143);
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(oracle), len), "oracle IP calc failed");

    protoswaptrickUpStreamPayload(t, &line, buf);

    struct ip_hdr *buf_ip = (struct ip_hdr *) sbufGetMutablePtr(buf);
    require(IPH_PROTO(buf_ip) == 143, "protocol was not swapped to 143");
    require(! lineGetRecalculateChecksum(&line), "protocol swap modified recalculate_checksum flag");
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle), len), "swap result mismatch with oracle");

    /* All bytes match the independently normalized oracle. */
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
    normalizeOracle(oracle);
    IPH_PROTO_SET(oracle_ip, 144);
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(oracle), len), "oracle IP calc failed");

    protoswaptrickDownStreamPayload(t, &line, buf);

    struct ip_hdr *buf_ip = (struct ip_hdr *) sbufGetMutablePtr(buf);
    require(IPH_PROTO(buf_ip) == 144, "UDP protocol was not swapped to 144");
    require(! lineGetRecalculateChecksum(&line), "UDP protocol swap modified recalculate_checksum flag");
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle), len), "UDP swap result mismatch with oracle");

    /* All bytes match the independently normalized oracle. */
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
    normalizeOracle(oracle);
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
    normalizeOracle(oracle);
    IPH_OFFSET_SET(oracle_ip, lwip_htons(IP_MF));
    IPH_PROTO_SET(oracle_ip, 143);
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(oracle), 60), "fragment oracle IP calc failed");

    protoswaptrickUpStreamPayload(t, &line, buf);

    require(IPH_PROTO(buf_ip) == 143, "fragmented packet protocol was not swapped");
    require(! lineGetRecalculateChecksum(&line), "fragmented packet swap modified flag");
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle), 60), "fragmented packet swap mismatch with oracle");

    sbuf_t        *later    = createIpv4TcpPacket(60, 5);
    struct ip_hdr *later_ip = (struct ip_hdr *) sbufGetMutablePtr(later);
    IPH_OFFSET_SET(later_ip, lwip_htons(3U));
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(later), 60), "later-fragment IP calc failed");

    protoswaptrickUpStreamPayload(t, &line, later);
    require(IPH_PROTO(later_ip) == 143,
            "later fragment did not receive the same configured mapping as the MF first fragment");

    protoswaptrickDownStreamPayload(t, &line, buf);
    protoswaptrickDownStreamPayload(t, &line, later);
    require(IPH_PROTO(buf_ip) == IPPROTO_TCP && IPH_PROTO(later_ip) == IPPROTO_TCP,
            "first and later fragments did not both restore to TCP");

    sbufDestroy(buf);
    sbufDestroy(later);
    sbufDestroy(oracle);
    destroyTestTunnel(t);
}

static void testProtocolSwapMalformedHeader(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};

    state->trick_proto_swap_tcp_number = 143;

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

    /* A later valid packet still receives the one configured mapping. */
    sbuf_t *valid = createIpv4TcpPacket(60, 5);
    protoswaptrickUpStreamPayload(t, &line, valid);
    require(IPH_PROTO((struct ip_hdr *) sbufGetMutablePtr(valid)) == 143,
            "valid packet did not receive the configured mapping after malformed packets");

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
    normalizeOracle(oracle);
    IPH_PROTO_SET(oracle_ip, IPPROTO_UDP);
    require(calcIpv4HeaderChecksum(sbufGetMutablePtr(oracle), len), "oracle IP calc failed");

    protoswaptrickUpStreamPayload(t, &line, buf);

    struct ip_hdr *buf_ip = (struct ip_hdr *) sbufGetMutablePtr(buf);
    require(IPH_PROTO(buf_ip) == IPPROTO_UDP, "protocol was not swapped to UDP");
    require(! lineGetRecalculateChecksum(&line), "protocol swap modified recalculate_checksum flag");
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle), len), "TCP->UDP swap result mismatch with oracle");

    /* Non-checksum transport fields remain unchanged. */
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

    require(! lineGetRecalculateChecksum(&line), "pre-encode checksum request was not consumed");
    struct ip_hdr *buf_ip = (struct ip_hdr *) sbufGetMutablePtr(buf);
    require(IPH_PROTO(buf_ip) == 143, "protocol was not swapped");

    sbufDestroy(buf);
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

/* Independent byte-sum oracle: zero is the canonical verification residual. */
static uint16_t transportResidual(const sbuf_t *buf, uint8_t protocol, bool mapped)
{
    const uint8_t       *bytes     = sbufGetRawPtr(buf);
    const struct ip_hdr *ip        = (const struct ip_hdr *) bytes;
    const uint8_t       *transport = bytes + IPH_HL_BYTES(ip);
    uint32_t             length    = lwip_ntohs(IPH_LEN(ip)) - IPH_HL_BYTES(ip);
    if (protocol == IPPROTO_UDP)
    {
        length = ((uint32_t) transport[4] << 8) | transport[5];
    }
    uint32_t sum = protocol + length;
    if (! mapped)
    {
        for (unsigned i = 12; i < 20; i += 2)
        {
            sum += ((uint32_t) bytes[i] << 8) | bytes[i + 1];
        }
    }
    for (uint32_t i = 0; i < length; i += 2)
    {
        sum += (uint32_t) transport[i] << 8;
        if (i + 1 < length)
        {
            sum += transport[i + 1];
        }
    }
    while (sum >> 16)
    {
        sum = (sum & 0xffffU) + (sum >> 16);
    }
    return sum == 0xffffU ? 0 : (uint16_t) sum;
}

static void requireOnlyTransitionBytesChanged(const sbuf_t *before, const sbuf_t *after, uint8_t protocol)
{
    const uint8_t *a = sbufGetRawPtr(before), *b = sbufGetRawPtr(after);
    uint32_t       field = (uint32_t) (a[0] & 15U) * 4U + (protocol == IPPROTO_TCP ? 16U : 6U);
    require(sbufGetLength(before) == sbufGetLength(after), "transition changed packet length");
    for (uint32_t i = 0; i < sbufGetLength(before); ++i)
    {
        if (i != 9 && i != 10 && i != 11 && i != field && i != field + 1)
        {
            require(a[i] == b[i], "transition changed unrelated bytes");
        }
    }
}

static void testAddressResidualMatrix(void)
{
    const uint32_t addresses[][2]                   = {{0x0a000001, 0x0a000002},
                                                       {0xcb00711e, 0x0a000002},
                                                       {0x0a000001, 0xc000020a},
                                                       {0xcb00711e, 0xc000020a},
                                                       {0, 0},
                                                       {0xffffffff, 0xffffffff},
                                                       {0x0000ffff, 0xffff0000}};
    tunnel_t      *t                                = createTestTunnel();
    testTunnelState(t)->trick_proto_swap_tcp_number = 50;
    testTunnelState(t)->trick_proto_swap_udp_number = 51;
    for (unsigned udp = 0; udp < 2; ++udp)
        for (unsigned direction = 0; direction < 2; ++direction)
            for (unsigned options = 0; options < 2; ++options)
                for (unsigned odd = 0; odd < 2; ++odd)
                    for (unsigned checksum_kind = 0; checksum_kind < 4; ++checksum_kind)
                        for (unsigned address = 0; address < ARRAY_SIZE(addresses); ++address)
                        {
                            const uint8_t  protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;
                            sbuf_t        *buf      = udp ? createIpv4UdpPacket((uint16_t) (80 + odd))
                                                          : createIpv4TcpPacket((uint16_t) (80 + odd), options ? 6 : 5);
                            struct ip_hdr *ip       = (struct ip_hdr *) sbufGetMutablePtr(buf);
                            if (udp && options)
                            {
                                uint8_t *raw = sbufGetMutablePtr(buf);
                                memmove(raw + 24, raw + 20, sbufGetLength(buf) - 20);
                                memset(raw + 20, 1, 4);
                                sbufSetLength(buf, sbufGetLength(buf) + 4);
                                IPH_VHL_SET(ip, 4, 6);
                                IPH_LEN_SET(ip, lwip_htons((uint16_t) sbufGetLength(buf)));
                            }
                            uint8_t *transport = sbufGetMutablePtr(buf) + IPH_HL_BYTES(ip);
                            if (! udp && options)
                            {
                                transport[12] = 0x60; /* Four bytes of TCP options. */
                                memset(transport + 20, 1, 4);
                            }
                            require(calcFullPacketChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf)),
                                    "matrix checksum build failed");
                            uint8_t *field = transport + (udp ? 6 : 16);
                            if (checksum_kind == 1)
                                field[0] = field[1] = 0;
                            if (checksum_kind == 2)
                                field[0] = field[1] = 0xff;
                            if (checksum_kind == 3)
                                field[0] ^= 0x42;
                            const bool disabled = udp && field[0] == 0 && field[1] == 0;
                            uint16_t   residual = transportResidual(buf, protocol, false);
                            line_t     line     = {0};
                            sbuf_t    *before   = sbufDuplicate(buf);
                            if (direction)
                                protoswaptrickDownStreamPayload(t, &line, buf);
                            else
                                protoswaptrickUpStreamPayload(t, &line, buf);
                            requireOnlyTransitionBytesChanged(before, buf, protocol);
                            sbufDestroy(before);
                            require(IPH_PROTO(ip) == (udp ? 51 : 50), "matrix encoding failed");
                            require(! lineGetRecalculateChecksum(&line), "delta invented a checksum request");
                            if (! disabled)
                                require(transportResidual(buf, protocol, true) == residual, "mapped residual changed");
                            else
                                require(field[0] == 0 && field[1] == 0, "disabled UDP changed on encode");
                            ip->src.addr  = lwip_htonl(addresses[address][0]);
                            ip->dest.addr = lwip_htonl(addresses[address][1]);
                            if (direction)
                                protoswaptrickUpStreamPayload(t, &line, buf);
                            else
                                protoswaptrickDownStreamPayload(t, &line, buf);
                            require(IPH_PROTO(ip) == protocol, "matrix decoding failed");
                            if (! disabled)
                            {
                                require(transportResidual(buf, protocol, false) == residual,
                                        "decoded residual changed");
                                if (udp)
                                    require(field[0] != 0 || field[1] != 0, "enabled UDP became disabled");
                            }
                            else
                                require(field[0] == 0 && field[1] == 0, "disabled UDP changed on decode");
                            /* Rewrite back to the original addresses through another mapped interval. */
                            require(protoswapApply(t, &line, buf), "second encode failed");
                            ip->src.addr  = PP_HTONL(0x0a000001);
                            ip->dest.addr = PP_HTONL(0x0a000002);
                            require(protoswapApply(t, &line, buf), "second decode failed");
                            if (! disabled)
                                require(transportResidual(buf, protocol, false) == residual,
                                        "rewrite-back residual changed");
                            sbufDestroy(buf);
                        }
    destroyTestTunnel(t);
}

static void testCorruptionAndPendingRequests(void)
{
    tunnel_t *t                                     = createTestTunnel();
    testTunnelState(t)->trick_proto_swap_tcp_number = 1;
    testTunnelState(t)->trick_proto_swap_udp_number = 51;
    for (unsigned udp = 0; udp < 2; ++udp)
    {
        const uint8_t protocol = udp ? IPPROTO_UDP : IPPROTO_TCP;
        line_t        line     = {0};
        sbuf_t       *buf      = udp ? createIpv4UdpPacket(61) : createIpv4TcpPacket(61, 5);
        uint8_t      *raw      = sbufGetMutablePtr(buf);
        raw[60] ^= 1;
        lineSetRecalculateChecksum(&line, true);
        protoswaptrickDownStreamPayload(t, &line, buf);
        require(! lineGetRecalculateChecksum(&line), "downstream encode left request pending");
        require(transportResidual(buf, protocol, true) == 0, "pending work ran in mapped representation");
        raw[60] ^= 2;
        require(protoswapApply(t, &line, buf), "corrupt packet failed structural preflight");
        require(transportResidual(buf, protocol, false) != 0, "wire corruption was repaired");
        require(protoswapApply(t, &line, buf), "corrupt native packet could not encode");
        lineSetRecalculateChecksum(&line, true);
        protoswaptrickDownStreamPayload(t, &line, buf);
        require(lineGetRecalculateChecksum(&line), "decode consumed downstream handoff request");
        require(packettunnelConsumeChecksumRequest(&line, buf), "native writer checksum repair failed");
        require(transportResidual(buf, protocol, false) == 0, "requested decode repair failed");
        require(! lineGetRecalculateChecksum(&line), "writer leaked request");
        sbufDestroy(buf);
    }
    destroyTestTunnel(t);
}

static sbuf_t *fragmentPacket(const sbuf_t *whole, uint32_t start, uint32_t count, bool more)
{
    const struct ip_hdr *original = sbufGetRawPtr(whole);
    uint16_t             header   = IPH_HL_BYTES(original);
    sbuf_t              *fragment = sbufCreate(header + count);
    sbufSetLength(fragment, header + count);
    uint8_t *raw = sbufGetMutablePtr(fragment);
    memcpy(raw, original, header);
    memcpy(raw + header, (const uint8_t *) original + header + start, count);
    struct ip_hdr *ip = (struct ip_hdr *) raw;
    IPH_LEN_SET(ip, lwip_htons((uint16_t) (header + count)));
    IPH_OFFSET_SET(ip, lwip_htons((uint16_t) (start / 8U | (more ? IP_MF : 0))));
    require(calcIpv4HeaderChecksum(raw, sbufGetLength(fragment)), "fragment header failed");
    return fragment;
}

static void testFragmentAddressNormalization(void)
{
    tunnel_t *t                                     = createTestTunnel();
    testTunnelState(t)->trick_proto_swap_tcp_number = 50;
    testTunnelState(t)->trick_proto_swap_udp_number = 51;
    for (unsigned udp = 0; udp < 2; ++udp)
        for (unsigned encoded_first = 0; encoded_first < 2; ++encoded_first)
            for (unsigned first_size = 8; first_size <= 24; first_size += 8)
                for (unsigned requested = 0; requested < 2; ++requested)
                {
                    uint8_t protocol    = udp ? IPPROTO_UDP : IPPROTO_TCP;
                    sbuf_t *whole       = udp ? createIpv4UdpPacket(84) : createIpv4TcpPacket(88, 6);
                    sbuf_t *reassembled = sbufDuplicate(whole);
                    line_t  sender = {0}, receiver = {0};
                    if (encoded_first)
                        require(protoswapApply(t, &sender, whole), "whole encode failed");
                    sbuf_t *fragments[3] = {fragmentPacket(whole, 0, first_size, true),
                                            fragmentPacket(whole, first_size, 24, true),
                                            fragmentPacket(whole, first_size + 24, 64 - first_size - 24, false)};
                    /* Reverse arrival order; no metadata is transferred between endpoints. */
                    for (int i = 2; i >= 0; --i)
                    {
                        sbuf_t *fragment = fragments[i];
                        if (! encoded_first)
                        {
                            lineSetRecalculateChecksum(&sender, requested != 0);
                            require(protoswapApply(t, &sender, fragment), "fragment encode failed");
                            require(! lineGetRecalculateChecksum(&sender), "fragment encode request not consumed");
                        }
                        struct ip_hdr *ip = (struct ip_hdr *) sbufGetMutablePtr(fragment);
                        require(IPH_PROTO(ip) == (udp ? 51 : 50), "fragment has wrong mapped protocol");
                        ip->src.addr  = PP_HTONL(0xcb00711e);
                        ip->dest.addr = PP_HTONL(0xc000020a);
                        require(protoswapApply(t, &receiver, fragment), "fragment decode failed");
                        require(IPH_PROTO(ip) == protocol, "fragment has wrong native protocol");
                        require(inet_chksum(ip, IPH_HL_BYTES(ip)) == 0, "fragment IPv4 checksum invalid");
                        uint32_t start = (lwip_ntohs(IPH_OFFSET(ip)) & IP_OFFMASK) * 8U;
                        memcpy(sbufGetMutablePtr(reassembled) + IPH_HL_BYTES(ip) + start,
                               sbufGetMutablePtr(fragment) + IPH_HL_BYTES(ip),
                               sbufGetLength(fragment) - IPH_HL_BYTES(ip));
                        sbufDestroy(fragment);
                    }
                    struct ip_hdr *ip = (struct ip_hdr *) sbufGetMutablePtr(reassembled);
                    ip->src.addr      = PP_HTONL(0xcb00711e);
                    ip->dest.addr     = PP_HTONL(0xc000020a);
                    require(transportResidual(reassembled, protocol, false) == 0,
                            "reassembled transport checksum invalid");
                    sbufDestroy(whole);
                    sbufDestroy(reassembled);
                }
    destroyTestTunnel(t);
}

static void testAtomicPreflightAndTrailingBytes(void)
{
    tunnel_t *t                                     = createTestTunnel();
    testTunnelState(t)->trick_proto_swap_tcp_number = 50;
    testTunnelState(t)->trick_proto_swap_udp_number = 51;
    for (unsigned kind = 0; kind < 11; ++kind)
        for (unsigned pending = 0; pending < 2; ++pending)
            for (unsigned mapped = 0; mapped < 2; ++mapped)
            {
                sbuf_t        *buf = kind == 4 || kind == 5 ? createIpv4UdpPacket(60) : createIpv4TcpPacket(60, 5);
                struct ip_hdr *ip  = (struct ip_hdr *) sbufGetMutablePtr(buf);
                if (mapped)
                    require(protoswapApply(t, &(line_t) {0}, buf), "malformed fixture encode failed");
                uint8_t *raw = sbufGetMutablePtr(buf);
                switch (kind)
                {
                case 0:
                    IPH_LEN_SET(ip, lwip_htons(37));
                    break; /* partial TCP checksum */
                case 1:
                    raw[32] = 0x40;
                    break;
                case 2:
                    raw[32] = 0xf0;
                    break;
                case 3:
                    IPH_OFFSET_SET(ip, lwip_htons(IP_MF));
                    IPH_LEN_SET(ip, lwip_htons(59));
                    break;
                case 4:
                    raw[24] = raw[25] = 0;
                    break;
                case 5:
                    raw[24] = 1;
                    break;
                case 6:
                    IPH_OFFSET_SET(ip, lwip_htons(IP_OFFMASK));
                    break;
                case 7:
                    IPH_OFFSET_SET(ip, lwip_htons(IP_DF | IP_MF));
                    break;
                case 8:
                    IPH_OFFSET_SET(ip, lwip_htons(2));
                    IPH_LEN_SET(ip, lwip_htons(21));
                    break;
                case 10:
                    IPH_OFFSET_SET(ip, lwip_htons(2));
                    IPH_LEN_SET(ip, lwip_htons(22));
                    break;
                case 9:
                    IPH_OFFSET_SET(ip, lwip_htons(IP_MF));
                    IPH_LEN_SET(ip, lwip_htons(20));
                    break;
                }
                sbuf_t *before = sbufDuplicate(buf);
                line_t  line   = {0};
                lineSetRecalculateChecksum(&line, pending != 0);
                require(! protoswapApply(t, &line, buf), "malformed transition succeeded");
                require(memoryEqual(sbufGetRawPtr(before), sbufGetRawPtr(buf), sbufGetLength(buf)),
                        "preflight mutated bytes");
                require(lineGetRecalculateChecksum(&line) == (pending != 0), "preflight changed request");
                sbufDestroy(before);
                sbufDestroy(buf);
            }
    sbuf_t  *buf = createIpv4TcpPacket(60, 5);
    uint8_t *raw = sbufGetMutablePtr(buf);
    memset(raw + 60, 0xa5, 7);
    sbufSetLength(buf, 67);
    sbuf_t *before = sbufDuplicate(buf);
    line_t  line   = {0};
    require(protoswapApply(t, &line, buf), "bounded trailing-byte transition failed");
    requireOnlyTransitionBytesChanged(before, buf, IPPROTO_TCP);
    require(transportResidual(buf, IPPROTO_TCP, true) == 0, "trailing bytes entered checksum");
    require(! packettunnelConsumeChecksumRequest(&line, buf), "writer accepted trailing bytes");
    sbufDestroy(before);
    sbufDestroy(buf);
    destroyTestTunnel(t);
}

int main(void)
{
    checkSumInit();
    testProtocolSwapTcpToCustomAndBack();
    testProtocolSwapUdpToCustomAndBack();
    testProtocolSwapWithIpOptions();
    testProtocolSwapFragmentedPacket();
    testProtocolSwapMalformedHeader();
    testProtocolSwapTcpToUdpDirect();
    testProtocolSwapPreExistingFlagPreserved();
    testRejectionAndNoMatch();
    testAddressResidualMatrix();
    testCorruptionAndPendingRequests();
    testFragmentAddressNormalization();
    testAtomicPreflightAndTrailingBytes();
    return 0;
}
