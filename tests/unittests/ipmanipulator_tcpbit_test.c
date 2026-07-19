#include "IpManipulator/structure.h"
#include "tricks/tcpbitchange/trick.h"

#include <stdio.h>
#include <stdlib.h>

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

    sbuf_t *buf = sbufCreate(128);
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
    IPH_CHKSUM_SET(ipheader, 0);
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
    tunnel_t                *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};
    sbuf_t                 *buf   = createTcpPacket(TCP_CWR | TCP_ECE | TCP_ACK | TCP_PSH, 0, false);

    state->down_tcp_bit_cwr_action = kDvsOff;

    tcpbitchangetrickDownStreamPayload(t, &line, &buf);

    require(buf != NULL, "packet was unexpectedly dropped");
    require(getAllTcpFlags(buf) == (TCP_ECE | TCP_ACK | TCP_PSH), "downstream CWR action did not clear CWR");
    require(lineGetRecalculateChecksum(&line), "downstream CWR change did not request checksum recalculation");

    sbufDestroy(buf);
    destroyTestTunnel(t);
}

static void testDownstreamCanCopyPacketCwr(void)
{
    tunnel_t                *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};
    sbuf_t                 *buf   = createTcpPacket(TCP_CWR | TCP_ACK, 0, false);

    state->down_tcp_bit_ece_action = kDvsPacketCwr;

    tcpbitchangetrickDownStreamPayload(t, &line, &buf);

    require(buf != NULL, "packet was unexpectedly dropped");
    require(getAllTcpFlags(buf) == (TCP_CWR | TCP_ECE | TCP_ACK), "downstream packet->cwr action did not see CWR");
    require(lineGetRecalculateChecksum(&line), "downstream packet->cwr change did not request checksum recalculation");

    sbufDestroy(buf);
    destroyTestTunnel(t);
}

static void testPreservedBitflagsCanClearCwrEceOnRestore(void)
{
    tunnel_t                *t     = createTestTunnel();
    ipmanipulator_tstate_t *state = testTunnelState(t);
    line_t                  line  = {0};
    sbuf_t                 *buf   = createTcpPacket(TCP_CWR | TCP_ECE | TCP_ACK, TCP_ACK, true);
    uint16_t                original_len = (uint16_t) sbufGetLength(buf);

    state->trick_preserve_tcp_bitflags = true;
    state->up_tcp_bit_ack_action          = kDvsToggle;

    tcpbitchangetrickDownStreamPayload(t, &line, &buf);

    require(buf != NULL, "packet was unexpectedly dropped");
    require(getAllTcpFlags(buf) == TCP_ACK, "preserved bitflags restore did not clear CWR/ECE");
    require(sbufGetLength(buf) == original_len - 1U, "preserved bitflags byte was not removed");
    require(lineGetRecalculateChecksum(&line), "preserved bitflags restore did not request checksum recalculation");

    sbufDestroy(buf);
    destroyTestTunnel(t);
}

int main(void)
{
    testDownstreamCanClearCwr();
    testDownstreamCanCopyPacketCwr();
    testPreservedBitflagsCanClearCwrEceOnRestore();

    return 0;
}
