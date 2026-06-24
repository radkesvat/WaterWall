#include "structure.h"

#include "loggers/network_logger.h"

// Detects a heartbeat packet: a minimal IPv4 packet tagged with kHeartbeatProtocol whose payload
// is filled with fill_byte. Real traffic is extremely unlikely to collide with this signature.
bool streamtopacketsFrameMatchesFillByte(const sbuf_t *packet, uint8_t fill_byte)
{
    if (sbufGetLength(packet) != kHeartbeatPacketSize)
    {
        return false;
    }

    const uint8_t *data = sbufGetRawPtr(packet);

    if ((data[0] >> 4) != 4 || (data[0] & 0x0FU) != (IP_HLEN / 4) || data[9] != kHeartbeatProtocol)
    {
        return false;
    }

    const uint8_t *payload = data + IP_HLEN;
    for (uint32_t i = 0; i < kSensitivePayloadSize; ++i)
    {
        if (payload[i] != fill_byte)
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

// Light, never-trusting structural check on a candidate IPv4 header (at least IP_HLEN bytes).
// This intentionally stays cheaper than the "loose" validation level: it only proves the head
// could be an IPv4 packet whose declared size is internally consistent and within the pipeline
// packet bound, so we know how many bytes a single packet would consume.
static inline bool streamtopacketsIpv4HeaderLooksValid(const uint8_t *header, uint16_t *total_len_out)
{
    const uint8_t  version    = (uint8_t) (header[0] >> 4);
    const uint8_t  header_len  = (uint8_t) ((header[0] & 0x0FU) * 4U);
    const uint16_t total_len   = (uint16_t) (((uint16_t) header[2] << 8) | (uint16_t) header[3]);

    *total_len_out = total_len;

    return version == 4 && header_len >= IP_HLEN && total_len >= header_len &&
           total_len <= (uint16_t) kMaxAllowedPacketLength;
}

// Drops leading bytes that cannot begin a valid IPv4 packet so the parser re-synchronizes on a
// garbage stream. It scans a bounded window for the next structurally-plausible IPv4 start and
// discards everything before it in one shot; if none is found it drops the inspected region while
// keeping the trailing bytes that might still be an incomplete header. Forward progress (>= 1
// byte) is always guaranteed, so no data pattern can stall the parser.
static void streamtopacketsDropResyncBytes(buffer_stream_t *stream)
{
    const size_t buffered = bufferstreamGetBufLen(stream);
    const size_t window   = buffered < (size_t) kResyncScanWindow ? buffered : (size_t) kResyncScanWindow;

    uint8_t scan[kResyncScanWindow];
    bufferstreamViewBytesAt(stream, 0, scan, window);

    size_t found = 0; // offset 0 is the head we already rejected
    for (size_t i = 1; i + (size_t) IP_HLEN <= window; ++i)
    {
        uint16_t total_len;
        if (streamtopacketsIpv4HeaderLooksValid(scan + i, &total_len))
        {
            found = i;
            break;
        }
    }

    const size_t drop = (found > 0) ? found : (window - ((size_t) IP_HLEN - 1));

    sbuf_t *dropped = bufferstreamReadExact(stream, drop);
    bufferpoolReuseBuffer(stream->pool, dropped);
}

// Validates an outgoing packet on the framing path. These adapters are IPv4-only, so non-IPv4
// (including IPv6) payloads are dropped. The IPv4 total length must also match the buffer length,
// otherwise forwarding it would desynchronize the size-based extractor on the peer.
bool streamtopacketsIsForwardableIpv4Packet(const sbuf_t *packet)
{
    const uint32_t len = sbufGetLength(packet);

    if (UNLIKELY(len < IP_HLEN || len > (uint32_t) kMaxAllowedPacketLength))
    {
        return false;
    }

    const struct ip_hdr *iphdr = (const struct ip_hdr *) sbufGetRawPtr(packet);

    if (UNLIKELY(IPH_V(iphdr) != 4))
    {
        return false;
    }

    return lwip_ntohs(IPH_LEN(iphdr)) == (uint16_t) len;
}

// Extracts exactly one IPv4 packet from the stream using the IPv4 total-length field as the frame
// size. Garbage is tolerated: a structurally-invalid head triggers re-synchronization, and a head
// that merely looks valid is trusted (worst case forwards a garbage-sized packet until the stream
// happens to realign). The stream is never trusted enough to read out of bounds or stall.
bool streamtopacketsTryReadIPv4Packet(buffer_stream_t *stream, sbuf_t **packet_out)
{
    assert(packet_out != NULL);
    *packet_out = NULL;

    while (true)
    {
        const size_t buffered = bufferstreamGetBufLen(stream);

        // Need a full minimum IPv4 header before any size field can be trusted.
        if (buffered < (size_t) IP_HLEN)
        {
            return false;
        }

        uint8_t header[IP_HLEN];
        bufferstreamViewBytesAt(stream, 0, header, IP_HLEN);

        uint16_t total_len;
        if (LIKELY(streamtopacketsIpv4HeaderLooksValid(header, &total_len)))
        {
            if (buffered < (size_t) total_len)
            {
                // Valid head, but the rest of the packet has not arrived yet.
                return false;
            }

            *packet_out = bufferstreamReadExact(stream, total_len);
            return true;
        }

        // IPv6 / garbage / inconsistent head: re-synchronize and retry.
        streamtopacketsDropResyncBytes(stream);
    }
}

// Builds and sends a heartbeat pong. The on-wire format is a raw concatenation of IPv4 packets, so
// the pong is itself a fully valid IPv4 packet tagged with kHeartbeatProtocol and a 0xDD payload.
bool streamtopacketsSendSensitivePong(tunnel_t *t, line_t *stream_line)
{
    sbuf_t *buf = bufferpoolGetSmallBuffer(lineGetBufferPool(stream_line));

    if (UNLIKELY(sbufGetMaximumWriteableSize(buf) < kHeartbeatPacketSize))
    {
        LOGW("StreamToPackets: dropping sensitive-mode pong because the buffer is too small");
        lineReuseBuffer(stream_line, buf);
        return true;
    }

    sbufSetLength(buf, kHeartbeatPacketSize);

    uint8_t *raw = sbufGetMutablePtr(buf);
    memorySet(raw, 0, IP_HLEN);

    struct ip_hdr *iphdr = (struct ip_hdr *) raw;
    IPH_VHL_SET(iphdr, 4, IP_HLEN / 4);
    IPH_LEN_SET(iphdr, lwip_htons((uint16_t) kHeartbeatPacketSize));
    IPH_TTL_SET(iphdr, 64);
    IPH_PROTO_SET(iphdr, kHeartbeatProtocol);
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, IP_HLEN));

    memorySet(raw + IP_HLEN, kSensitivePongByte, kSensitivePayloadSize);

    tunnelPrevDownStreamPayload(t, stream_line, buf);
    return lineIsAlive(stream_line);
}
