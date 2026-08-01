#include "IpManipulator/structure.h"
#include "tricks/tcpbitchange/trick.h"
#include "wchecksum.h"
#include "wlibc.h"

enum
{
    kTcpAllFlagsMask = 0x00FF
};

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

    t->tstate_size = sizeof(ipmanipulator_tstate_t);
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

static sbuf_t *createTcpPacket(uint8_t flags, uint8_t extra_tail_byte, bool append_extra_tail)
{
    const uint16_t ip_header_len  = (uint16_t) sizeof(struct ip_hdr);
    const uint16_t tcp_header_len = (uint16_t) sizeof(struct tcp_hdr);
    const uint16_t payload_len    = 4;
    const uint16_t packet_len =
        (uint16_t) (ip_header_len + tcp_header_len + payload_len + (append_extra_tail ? 1U : 0U));

    sbuf_t *buf = sbufCreate(256);
    require(buf != NULL, "failed to allocate packet buffer");
    sbufSetLength(buf, packet_len);

    uint8_t *packet = sbufGetMutablePtr(buf);
    memoryZero(packet, packet_len);

    struct ip_hdr  *ipheader   = (struct ip_hdr *) packet;
    struct tcp_hdr *tcp_header = (struct tcp_hdr *) (packet + ip_header_len);
    uint8_t        *payload    = packet + ip_header_len + tcp_header_len;

    IPH_VHL_SET(ipheader, 4, ip_header_len / 4U);
    IPH_TOS_SET(ipheader, 0);
    IPH_LEN_SET(ipheader, lwip_htons(packet_len));
    IPH_ID_SET(ipheader, lwip_htons(1));
    IPH_OFFSET_SET(ipheader, 0);
    IPH_TTL_SET(ipheader, 64);
    IPH_PROTO_SET(ipheader, IPPROTO_TCP);
    ipheader->src.addr  = PP_HTONL(LWIP_MAKEU32(10, 0, 0, 1));
    ipheader->dest.addr = PP_HTONL(LWIP_MAKEU32(10, 0, 0, 2));

    tcp_header->src   = lwip_htons(40123);
    tcp_header->dest  = lwip_htons(40234);
    tcp_header->seqno = lwip_htonl(0x10203040U);
    tcp_header->ackno = lwip_htonl(0x50607080U);
    TCPH_HDRLEN_FLAGS_SET(tcp_header, tcp_header_len / 4U, flags);
    tcp_header->wnd  = lwip_htons(64240U);
    tcp_header->urgp = 0;

    payload[0] = 0xA1;
    payload[1] = 0xB2;
    payload[2] = 0xC3;
    payload[3] = 0xD4;

    if (append_extra_tail)
    {
        packet[packet_len - 1U] = extra_tail_byte;
    }

    require(calcFullPacketChecksum(packet, packet_len), "failed to compute initial checksums");
    return buf;
}

static uint8_t getAllTcpFlags(sbuf_t *buf)
{
    uint8_t        *packet     = sbufGetMutablePtr(buf);
    struct tcp_hdr *tcp_header = (struct tcp_hdr *) (packet + sizeof(struct ip_hdr));

    return (uint8_t) (lwip_ntohs(tcp_header->_hdrlen_rsvd_flags) & kTcpAllFlagsMask);
}

static void testDownstreamCanClearCwr(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};
    sbuf_t                 *buf   = createTcpPacket(TCP_CWR | TCP_ECE | TCP_ACK | TCP_PSH, 0, false);

    uint8_t expected_flags = TCP_ECE | TCP_ACK | TCP_PSH;
    sbuf_t *oracle         = createTcpPacket(expected_flags, 0, false);

    state->down_tcp_bit_cwr_action = kDvsOff;

    tcpbitchangetrickDownStreamPayload(t, &line, &buf);

    require(buf != NULL, "packet was unexpectedly dropped");
    require(getAllTcpFlags(buf) == expected_flags, "downstream CWR action did not clear CWR");
    require(! lineGetRecalculateChecksum(&line), "downstream simple CWR change modified recalculate_checksum flag");
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle), sbufGetLength(buf)),
            "downstream CWR cleared packet mismatch with oracle");

    sbufDestroy(buf);
    sbufDestroy(oracle);
    destroyTestTunnel(t);
}

static void testDownstreamCanCopyPacketCwr(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};
    sbuf_t                 *buf   = createTcpPacket(TCP_CWR | TCP_ACK, 0, false);

    uint8_t expected_flags = TCP_CWR | TCP_ECE | TCP_ACK;
    sbuf_t *oracle         = createTcpPacket(expected_flags, 0, false);

    state->down_tcp_bit_ece_action = kDvsPacketCwr;

    tcpbitchangetrickDownStreamPayload(t, &line, &buf);

    require(buf != NULL, "packet was unexpectedly dropped");
    require(getAllTcpFlags(buf) == expected_flags, "downstream packet->cwr action did not see CWR");
    require(! lineGetRecalculateChecksum(&line), "downstream packet->cwr change modified recalculate_checksum flag");
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle), sbufGetLength(buf)),
            "downstream copy CWR packet mismatch with oracle");

    sbufDestroy(buf);
    sbufDestroy(oracle);
    destroyTestTunnel(t);
}

static void testPreservedBitflagsCanClearCwrEceOnRestore(void)
{
    tunnel_t               *t            = createTestTunnel();
    ipmanipulator_tstate_t *state        = testTunnelState(t);
    line_t                  line         = {0};
    sbuf_t                 *buf          = createTcpPacket(TCP_CWR | TCP_ECE | TCP_ACK, TCP_ACK, true);
    uint16_t                original_len = (uint16_t) sbufGetLength(buf);

    state->trick_preserve_tcp_bitflags = true;
    state->up_tcp_bit_ack_action       = kDvsToggle;

    tcpbitchangetrickDownStreamPayload(t, &line, &buf);

    require(buf != NULL, "packet was unexpectedly dropped");
    require(getAllTcpFlags(buf) == TCP_ACK, "preserved bitflags restore did not clear CWR/ECE");
    require(sbufGetLength(buf) == original_len - 1U, "preserved bitflags byte was not removed");
    require(lineGetRecalculateChecksum(&line), "preserved bitflags restore did not request checksum recalculation");

    require(calcFullPacketChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf)),
            "full recalculation failed after restore");
    sbuf_t *oracle = createTcpPacket(TCP_ACK, 0, false);
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle), sbufGetLength(buf)),
            "restored preserve-bitflags packet mismatch with oracle");

    sbufDestroy(buf);
    sbufDestroy(oracle);
    destroyTestTunnel(t);
}

static void testPreservedBitflagsAppend(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};
    sbuf_t                 *buf   = createTcpPacket(TCP_SYN, 0, false);

    state->trick_preserve_tcp_bitflags = true;
    state->up_tcp_bit_syn_action       = kDvsOff;

    tcpbitchangetrickUpStreamPayload(t, &line, &buf);

    require(buf != NULL, "packet was unexpectedly dropped");
    require(getAllTcpFlags(buf) == 0, "preserve append did not clear SYN bit");
    require(lineGetRecalculateChecksum(&line), "preserve append did not request checksum recalculation");

    uint8_t *raw = sbufGetMutablePtr(buf);
    uint16_t len = (uint16_t) sbufGetLength(buf);
    require(raw[len - 1] == TCP_SYN, "preserve append did not append original SYN flag byte");

    require(calcFullPacketChecksum(raw, len), "full recalculation failed after preserve append");
    sbufDestroy(buf);
    destroyTestTunnel(t);
}

static void testSimpleTcpFlagPreExistingFlagPreserved(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};
    sbuf_t                 *buf   = createTcpPacket(TCP_ACK, 0, false);

    lineSetRecalculateChecksum(&line, true);
    state->up_tcp_bit_psh_action = kDvsOn;

    tcpbitchangetrickUpStreamPayload(t, &line, &buf);

    require(buf != NULL, "packet was unexpectedly dropped");
    require(getAllTcpFlags(buf) == (TCP_ACK | TCP_PSH), "simple flag change failed");
    require(lineGetRecalculateChecksum(&line), "pre-existing recalculate_checksum flag was cleared");

    require(calcFullPacketChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf)), "full recalculation failed");
    sbuf_t *oracle = createTcpPacket(TCP_ACK | TCP_PSH, 0, false);
    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(oracle), sbufGetLength(buf)),
            "pending-flag packet mismatch with oracle after full recalculation");

    sbufDestroy(buf);
    sbufDestroy(oracle);
    destroyTestTunnel(t);
}

static void testPreserveRejectsForgedIpv4TotalLength(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};

    state->trick_preserve_tcp_bitflags = true;
    state->up_tcp_bit_syn_action       = kDvsOff;

    sbuf_t *append_buf = createTcpPacket(TCP_SYN, 0, false);
    IPH_LEN_SET((struct ip_hdr *) sbufGetMutablePtr(append_buf), lwip_htons(60000));
    uint32_t append_len = sbufGetLength(append_buf);
    uint8_t  append_before[64];
    require(append_len <= sizeof(append_before), "append rejection fixture exceeded snapshot");
    memoryCopy(append_before, sbufGetRawPtr(append_buf), append_len);

    tcpbitchangetrickUpStreamPayload(t, &line, &append_buf);

    require(append_buf != NULL, "forged append packet was unexpectedly consumed");
    require(sbufGetLength(append_buf) == append_len, "forged append packet length changed");
    require(memoryEqual(sbufGetRawPtr(append_buf), append_before, append_len), "forged append packet bytes changed");
    require(! lineGetRecalculateChecksum(&line), "forged append packet requested checksum recalculation");
    sbufDestroy(append_buf);

    sbuf_t *restore_buf = createTcpPacket(0, TCP_SYN, true);
    IPH_LEN_SET((struct ip_hdr *) sbufGetMutablePtr(restore_buf), lwip_htons(60000));
    uint32_t restore_len = sbufGetLength(restore_buf);
    uint8_t  restore_before[64];
    require(restore_len <= sizeof(restore_before), "restore rejection fixture exceeded snapshot");
    memoryCopy(restore_before, sbufGetRawPtr(restore_buf), restore_len);

    tcpbitchangetrickDownStreamPayload(t, &line, &restore_buf);

    require(restore_buf != NULL, "forged restore packet was unexpectedly consumed");
    require(sbufGetLength(restore_buf) == restore_len, "forged restore packet length changed");
    require(memoryEqual(sbufGetRawPtr(restore_buf), restore_before, restore_len),
            "forged restore packet bytes changed");
    require(! lineGetRecalculateChecksum(&line), "forged restore packet requested checksum recalculation");
    sbufDestroy(restore_buf);

    destroyTestTunnel(t);
}

static void testPreservedBitflagsRoundTrip(void)
{
    tunnel_t               *t            = createTestTunnel();
    ipmanipulator_tstate_t *state        = testTunnelState(t);
    line_t                  line         = {0};
    sbuf_t                 *buf          = createTcpPacket(TCP_SYN | TCP_ACK, 0, false);
    uint32_t                original_len = sbufGetLength(buf);
    uint8_t                 original[64];

    require(original_len <= sizeof(original), "round-trip fixture exceeded snapshot");
    memoryCopy(original, sbufGetRawPtr(buf), original_len);

    state->trick_preserve_tcp_bitflags = true;
    state->up_tcp_bit_syn_action       = kDvsOff;

    tcpbitchangetrickUpStreamPayload(t, &line, &buf);
    require(buf != NULL && sbufGetLength(buf) == original_len + 1U, "well-formed append boundary was rejected");

    tcpbitchangetrickDownStreamPayload(t, &line, &buf);
    require(buf != NULL, "well-formed restore boundary was rejected");
    require(sbufGetLength(buf) == original_len, "preserve round trip did not restore the original length");
    require(memoryEqual(sbufGetRawPtr(buf), original, original_len),
            "preserve append/restore round trip changed packet bytes");

    sbufDestroy(buf);
    destroyTestTunnel(t);
}

static void testNoOpAndRejection(void)
{
    tunnel_t               *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};

    state->up_tcp_bit_psh_action = kDvsOn;

    /* 1. No-op (new_flags == original_flags) */
    sbuf_t *buf    = createTcpPacket(TCP_ACK | TCP_PSH, 0, false);
    sbuf_t *before = sbufCreate(256);
    sbufSetLength(before, sbufGetLength(buf));
    memoryCopy(sbufGetMutablePtr(before), sbufGetRawPtr(buf), sbufGetLength(buf));

    tcpbitchangetrickUpStreamPayload(t, &line, &buf);

    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(before), sbufGetLength(buf)), "no-op modified packet");
    require(! lineGetRecalculateChecksum(&line), "no-op modified recalculate_checksum flag");
    sbufDestroy(buf);

    /* 2. Short buffer (< sizeof(struct ip_hdr)) */
    buf = sbufCreate(256);
    sbufSetLength(buf, 10);
    memoryZero(sbufGetMutablePtr(buf), 10);

    tcpbitchangetrickUpStreamPayload(t, &line, &buf);
    require(sbufGetLength(buf) == 10, "short buffer modified");
    require(! lineGetRecalculateChecksum(&line), "short buffer modified flag");
    sbufDestroy(buf);

    /* 3. Fragmented IPv4 packet */
    buf                     = createTcpPacket(TCP_ACK, 0, false);
    struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);
    IPH_OFFSET_SET(ipheader, lwip_htons(IP_MF));
    sbufSetLength(before, sbufGetLength(buf));
    memoryCopy(sbufGetMutablePtr(before), sbufGetRawPtr(buf), sbufGetLength(buf));

    tcpbitchangetrickUpStreamPayload(t, &line, &buf);

    require(memoryEqual(sbufGetRawPtr(buf), sbufGetRawPtr(before), sbufGetLength(buf)), "fragmented packet modified");
    require(! lineGetRecalculateChecksum(&line), "fragmented packet modified flag");
    sbufDestroy(buf);

    /* 4. IPv6-looking input (IPH_V = 6) */
    buf = sbufCreate(256);
    sbufSetLength(buf, 40);
    uint8_t *raw = sbufGetMutablePtr(buf);
    memoryZero(raw, 40);
    raw[0] = 0x60;
    uint8_t before6[40];
    memoryCopy(before6, raw, 40);

    tcpbitchangetrickUpStreamPayload(t, &line, &buf);
    require(memoryEqual(sbufGetRawPtr(buf), before6, 40), "IPv6 packet modified");
    require(! lineGetRecalculateChecksum(&line), "IPv6 packet modified flag");
    sbufDestroy(buf);

    /* 5. Truncated TCP header (sbuf len < iphdr_len + sizeof(struct tcp_hdr)) */
    buf = createTcpPacket(TCP_ACK, 0, false);
    sbufSetLength(buf, 30); /* 20 IP + 10 TCP bytes */
    memoryCopy(before, sbufGetRawPtr(buf), 30);

    tcpbitchangetrickUpStreamPayload(t, &line, &buf);
    require(memoryEqual(sbufGetRawPtr(buf), before, 30), "truncated TCP header packet modified");
    require(! lineGetRecalculateChecksum(&line), "truncated TCP header modified flag");
    sbufDestroy(buf);

    /* 6. Invalid TCP data offset (data_offset = 4 < 5) */
    buf                  = createTcpPacket(TCP_ACK, 0, false);
    struct tcp_hdr *tcph = (struct tcp_hdr *) (sbufGetMutablePtr(buf) + 20);
    TCPH_HDRLEN_FLAGS_SET(tcph, 4, TCP_ACK);
    memoryCopy(before, sbufGetRawPtr(buf), sbufGetLength(buf));

    tcpbitchangetrickUpStreamPayload(t, &line, &buf);
    require(memoryEqual(sbufGetRawPtr(buf), before, sbufGetLength(buf)), "invalid TCP data offset packet modified");
    require(! lineGetRecalculateChecksum(&line), "invalid TCP data offset modified flag");
    sbufDestroy(buf);

    /* 7. Invalid IP header length (IHL = 4 < 5) */
    buf      = createTcpPacket(TCP_ACK, 0, false);
    ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);
    IPH_VHL_SET(ipheader, 4, 4);
    memoryCopy(before, sbufGetRawPtr(buf), sbufGetLength(buf));

    tcpbitchangetrickUpStreamPayload(t, &line, &buf);
    require(memoryEqual(sbufGetRawPtr(buf), before, sbufGetLength(buf)), "invalid IP IHL packet modified");
    require(! lineGetRecalculateChecksum(&line), "invalid IP IHL modified flag");
    sbufDestroy(buf);

    /* 8. Invalid IP total length below IHL (total_len = 10 < IHL 20) */
    buf      = createTcpPacket(TCP_ACK, 0, false);
    ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);
    IPH_LEN_SET(ipheader, lwip_htons(10));
    memoryCopy(before, sbufGetRawPtr(buf), sbufGetLength(buf));

    tcpbitchangetrickUpStreamPayload(t, &line, &buf);
    require(memoryEqual(sbufGetRawPtr(buf), before, sbufGetLength(buf)), "IP total_len < IHL packet modified");
    require(! lineGetRecalculateChecksum(&line), "IP total_len < IHL modified flag");
    sbufDestroy(buf);

    /* 9. Invalid IP total length beyond buffer (total_len = 200 > sbuf len 60) */
    buf      = createTcpPacket(TCP_ACK, 0, false);
    ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);
    IPH_LEN_SET(ipheader, lwip_htons(200));
    sbufSetLength(buf, 60);
    memoryCopy(before, sbufGetRawPtr(buf), 60);

    tcpbitchangetrickUpStreamPayload(t, &line, &buf);
    require(memoryEqual(sbufGetRawPtr(buf), before, 60), "IP total_len > buffer len packet modified");
    require(! lineGetRecalculateChecksum(&line), "IP total_len > buffer len modified flag");
    sbufDestroy(buf);

    sbufDestroy(before);
    destroyTestTunnel(t);
}

int main(void)
{
    checkSumInit();
    testDownstreamCanClearCwr();
    testDownstreamCanCopyPacketCwr();
    testPreservedBitflagsCanClearCwrEceOnRestore();
    testPreservedBitflagsAppend();
    testSimpleTcpFlagPreExistingFlagPreserved();
    testPreserveRejectsForgedIpv4TotalLength();
    testPreservedBitflagsRoundTrip();
    testNoOpAndRejection();

    return 0;
}
