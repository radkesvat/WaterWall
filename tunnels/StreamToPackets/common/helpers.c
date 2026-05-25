#include "structure.h"

#include "loggers/network_logger.h"

bool streamtopacketsFrameMatchesFillByte(const sbuf_t *packet, uint8_t fill_byte)
{
    if (sbufGetLength(packet) != kSensitivePayloadSize)
    {
        return false;
    }

    const uint8_t *data = sbufGetRawPtr(packet);

    for (uint32_t i = 0; i < kSensitivePayloadSize; ++i)
    {
        if (data[i] != fill_byte)
        {
            return false;
        }
    }

    return true;
}

bool streamtopacketsReadStreamIsOverflowed(buffer_stream_t *read_stream)
{
    if (bufferstreamGetBufLen(read_stream) > kMaxBufferSize)
    {
        LOGW("StreamToPackets: read stream overflow, size: %zu, limit: %zu", bufferstreamGetBufLen(read_stream),
             (size_t) kMaxBufferSize);
        return true;
    }

    return false;
}

static const char *streamtopacketsValidationLevelName(streamtopackets_packet_validation_level_t level)
{
    switch (level)
    {
    case kStreamToPacketsPacketValidationNone:
        return "none";
    case kStreamToPacketsPacketValidationLoose:
        return "loose";
    case kStreamToPacketsPacketValidationHard:
        return "hard";
    default:
        return "unknown";
    }
}

static bool streamtopacketsDropInvalidPacket(streamtopackets_packet_validation_level_t level, const char *direction,
                                             const char *reason)
{
    LOGW("StreamToPackets: dropping packet during %s packet validation (%s): %s", direction,
         streamtopacketsValidationLevelName(level), reason);
    return false;
}

static uint32_t streamtopacketsChecksumPseudoHeader(const struct ip_hdr *iphdr, uint8_t proto, uint16_t length)
{
    uint32_t sum   = 0;
    uint32_t src_h = lwip_ntohl(iphdr->src.addr);
    uint32_t dst_h = lwip_ntohl(iphdr->dest.addr);

    sum += (src_h >> 16) & 0xFFFFU;
    sum += src_h & 0xFFFFU;
    sum += (dst_h >> 16) & 0xFFFFU;
    sum += dst_h & 0xFFFFU;
    sum += proto;
    sum += length;

    return sum;
}

static bool streamtopacketsValidateIpv4PacketHeader(streamtopackets_packet_validation_level_t level, sbuf_t *packet,
                                                    const char *direction, struct ip_hdr **iphdr_out,
                                                    uint16_t *header_len_out, uint16_t *total_len_out)
{
    uint32_t packet_len = sbufGetLength(packet);

    if (packet_len < sizeof(struct ip_hdr))
    {
        return streamtopacketsDropInvalidPacket(level, direction, "packet is smaller than the IPv4 header");
    }

    struct ip_hdr *iphdr = (struct ip_hdr *) sbufGetMutablePtr(packet);
    if (IPH_V(iphdr) != 4)
    {
        return streamtopacketsDropInvalidPacket(level, direction, "unsupported IP version");
    }

    uint16_t header_len = IPH_HL_BYTES(iphdr);
    if (header_len < IP_HLEN || header_len > IP_HLEN_MAX)
    {
        return streamtopacketsDropInvalidPacket(level, direction, "invalid IPv4 header length");
    }

    if (header_len > packet_len)
    {
        return streamtopacketsDropInvalidPacket(level, direction, "buffer is shorter than the IPv4 header length");
    }

    uint16_t total_len = lwip_ntohs(IPH_LEN(iphdr));
    if (total_len < header_len)
    {
        return streamtopacketsDropInvalidPacket(level, direction, "IPv4 total length is smaller than the header");
    }

    if (total_len < packet_len)
    {
        return streamtopacketsDropInvalidPacket(level, direction,
                                                "IPv4 total length is smaller than the packet buffer");
    }

    if (total_len > packet_len)
    {
        return streamtopacketsDropInvalidPacket(level, direction, "buffer is shorter than the IPv4 total length");
    }

    *iphdr_out       = iphdr;
    *header_len_out  = header_len;
    *total_len_out   = total_len;
    return true;
}

static bool streamtopacketsValidateIpv4HeaderChecksum(streamtopackets_packet_validation_level_t level,
                                                       struct ip_hdr *iphdr, uint16_t header_len,
                                                       const char *direction)
{
    uint16_t original_checksum = IPH_CHKSUM(iphdr);

    IPH_CHKSUM_SET(iphdr, 0);
    uint16_t expected_checksum = inet_chksum(iphdr, header_len);
    IPH_CHKSUM_SET(iphdr, original_checksum);

    if (original_checksum != expected_checksum)
    {
        return streamtopacketsDropInvalidPacket(level, direction, "invalid IPv4 header checksum");
    }

    return true;
}

static bool streamtopacketsValidateTcpChecksum(streamtopackets_packet_validation_level_t level, struct ip_hdr *iphdr,
                                               uint16_t header_len, uint16_t total_len, const char *direction)
{
    uint16_t transport_len = (uint16_t) (total_len - header_len);
    if (transport_len < TCP_HLEN)
    {
        return streamtopacketsDropInvalidPacket(level, direction, "TCP packet is smaller than the minimum header");
    }

    uint8_t        *transport = ((uint8_t *) iphdr) + header_len;
    struct tcp_hdr *tcphdr    = (struct tcp_hdr *) transport;
    uint16_t        tcp_hlen  = TCPH_HDRLEN_BYTES(tcphdr);

    if (tcp_hlen < TCP_HLEN || tcp_hlen > transport_len)
    {
        return streamtopacketsDropInvalidPacket(level, direction, "invalid TCP header length");
    }

    uint16_t original_checksum = tcphdr->chksum;
    tcphdr->chksum             = 0;
    uint16_t expected_checksum = calcGenericChecksum(
        transport, transport_len, streamtopacketsChecksumPseudoHeader(iphdr, IP_PROTO_TCP, transport_len));
    tcphdr->chksum = original_checksum;

    if (original_checksum != expected_checksum)
    {
        return streamtopacketsDropInvalidPacket(level, direction, "invalid TCP checksum");
    }

    return true;
}

static bool streamtopacketsValidateUdpChecksum(streamtopackets_packet_validation_level_t level, struct ip_hdr *iphdr,
                                               uint16_t header_len, uint16_t total_len, const char *direction)
{
    uint16_t transport_len = (uint16_t) (total_len - header_len);
    if (transport_len < UDP_HLEN)
    {
        return streamtopacketsDropInvalidPacket(level, direction, "UDP packet is smaller than the minimum header");
    }

    uint8_t        *transport = ((uint8_t *) iphdr) + header_len;
    struct udp_hdr *udphdr    = (struct udp_hdr *) transport;
    uint16_t        udp_len   = lwip_ntohs(udphdr->len);

    if (udp_len < UDP_HLEN || udp_len > transport_len)
    {
        return streamtopacketsDropInvalidPacket(level, direction, "invalid UDP length");
    }

    if (udphdr->chksum == 0)
    {
        return true;
    }

    uint16_t original_checksum = udphdr->chksum;
    udphdr->chksum             = 0;
    uint16_t expected_checksum = calcGenericChecksum(
        transport, udp_len, streamtopacketsChecksumPseudoHeader(iphdr, IP_PROTO_UDP, udp_len));
    udphdr->chksum = original_checksum;

    if (expected_checksum == 0)
    {
        expected_checksum = 0xFFFFU;
    }

    if (original_checksum != expected_checksum)
    {
        return streamtopacketsDropInvalidPacket(level, direction, "invalid UDP checksum");
    }

    return true;
}

static bool streamtopacketsValidateIcmpChecksum(streamtopackets_packet_validation_level_t level, struct ip_hdr *iphdr,
                                                uint16_t header_len, uint16_t total_len, const char *direction)
{
    uint16_t transport_len = (uint16_t) (total_len - header_len);
    if (transport_len < sizeof(struct icmp_hdr))
    {
        return streamtopacketsDropInvalidPacket(level, direction, "ICMP packet is smaller than the minimum header");
    }

    uint8_t         *transport = ((uint8_t *) iphdr) + header_len;
    struct icmp_hdr *icmphdr   = (struct icmp_hdr *) transport;

    uint16_t original_checksum = icmphdr->chksum;
    icmphdr->chksum            = 0;
    uint16_t expected_checksum = calcGenericChecksum(transport, transport_len, 0);
    icmphdr->chksum = original_checksum;

    if (original_checksum != expected_checksum)
    {
        return streamtopacketsDropInvalidPacket(level, direction, "invalid ICMP checksum");
    }

    return true;
}

bool streamtopacketsValidatePacket(streamtopackets_packet_validation_level_t level, sbuf_t *packet,
                                   const char *direction)
{
    if (level == kStreamToPacketsPacketValidationNone)
    {
        return true;
    }

    struct ip_hdr *iphdr      = NULL;
    uint16_t       header_len = 0;
    uint16_t       total_len  = 0;

    if (! streamtopacketsValidateIpv4PacketHeader(level, packet, direction, &iphdr, &header_len, &total_len))
    {
        return false;
    }

    if (level == kStreamToPacketsPacketValidationLoose)
    {
        return true;
    }

    if (! streamtopacketsValidateIpv4HeaderChecksum(level, iphdr, header_len, direction))
    {
        return false;
    }

    uint16_t frag_field = lwip_ntohs(IPH_OFFSET(iphdr));
    if ((frag_field & (IP_MF | IP_OFFMASK)) != 0)
    {
        return true;
    }

    switch (IPH_PROTO(iphdr))
    {
    case IP_PROTO_TCP:
        return streamtopacketsValidateTcpChecksum(level, iphdr, header_len, total_len, direction);
    case IP_PROTO_UDP:
        return streamtopacketsValidateUdpChecksum(level, iphdr, header_len, total_len, direction);
    case IP_PROTO_ICMP:
        return streamtopacketsValidateIcmpChecksum(level, iphdr, header_len, total_len, direction);
    default:
        return true;
    }
}

void streamtopacketsRecalculateChecksumIfRequested(line_t *l, sbuf_t *buf)
{
    if (! lineGetRecalculateChecksum(l))
    {
        return;
    }

    if (sbufGetLength(buf) >= sizeof(struct ip_hdr))
    {
        struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);

        if (IPH_V(ipheader) == 4)
        {
            calcFullPacketChecksum(sbufGetMutablePtr(buf));
        }
    }

    lineSetRecalculateChecksum(l, false);
}

bool streamtopacketsTryReadIPv4Packet(buffer_stream_t *stream, sbuf_t **packet_out)
{
    assert(packet_out != NULL);
    *packet_out = NULL;

    if (bufferstreamGetBufLen(stream) < kHeaderSize + 1)
    {
        return false;
    }

    uint8_t packet_first_bytes[kHeaderSize];
    bufferstreamViewBytesAt(stream, 0, packet_first_bytes, kHeaderSize);

    uint16_t total_packet_size_network;
    sbufByteCopy(&total_packet_size_network, packet_first_bytes, (uint32_t) sizeof(total_packet_size_network));
    uint16_t total_packet_size = ntohs(total_packet_size_network);
    
    if (total_packet_size < 1 || ((uint32_t) (total_packet_size  + kHeaderSize)) > (uint32_t) bufferstreamGetBufLen(stream))
    {
        return false;
    }

    // Read the complete packet (header + payload)
    *packet_out = bufferstreamReadExact(stream, kHeaderSize + total_packet_size);
    sbufShiftRight(*packet_out, kHeaderSize);

    return true;

}

bool streamtopacketsSendSensitivePong(tunnel_t *t, line_t *stream_line)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(stream_line));

    if (sbufGetLeftCapacity(buf) < kHeaderSize)
    {
        LOGW("StreamToPackets: dropping sensitive-mode pong because left padding is smaller than header size");
        lineReuseBuffer(stream_line, buf);
        return true;
    }

    sbufSetLength(buf, kSensitivePayloadSize);
    memorySet(sbufGetMutablePtr(buf), kSensitivePongByte, kSensitivePayloadSize);

    sbufShiftLeft(buf, kHeaderSize);
    sbufWriteUnAlignedUI16(buf, htons((uint16_t) kSensitivePayloadSize));

    tunnelPrevDownStreamPayload(t, stream_line, buf);
    return lineIsAlive(stream_line);
}
