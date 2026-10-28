#include "Ipv4StreamCodec/codec.h"

#include "wchecksum.h"

enum
{
    kResyncScanWindow = 256
};

_Static_assert(kMaxAllowedPacketLength >= IP_HLEN && kMaxAllowedPacketLength <= UINT16_MAX,
               "IPv4 stream packet bound must fit the wire length");

static uint32_t ipv4streamChecksumPseudoHeader(const struct ip_hdr *iphdr, uint8_t proto, uint16_t length)
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

static const char *ipv4streamValidateIpv4PacketHeader(sbuf_t *packet, struct ip_hdr **iphdr_out,
                                                      uint16_t *header_len_out, uint16_t *total_len_out)
{
    uint32_t packet_len = sbufGetLength(packet);

    if (packet_len < sizeof(struct ip_hdr))
    {
        return "packet is smaller than the IPv4 header";
    }

    struct ip_hdr *iphdr = (struct ip_hdr *) sbufGetMutablePtr(packet);
    if (IPH_V(iphdr) != 4)
    {
        return "unsupported IP version";
    }

    uint16_t header_len = IPH_HL_BYTES(iphdr);
    if (header_len < IP_HLEN)
    {
        return "invalid IPv4 header length";
    }

    if (header_len > packet_len)
    {
        return "buffer is shorter than the IPv4 header length";
    }

    uint16_t total_len = lwip_ntohs(IPH_LEN(iphdr));
    if (total_len < header_len)
    {
        return "IPv4 total length is smaller than the header";
    }

    if (total_len < packet_len)
    {
        return "IPv4 total length is smaller than the packet buffer";
    }

    if (total_len > packet_len)
    {
        return "buffer is shorter than the IPv4 total length";
    }

    *iphdr_out      = iphdr;
    *header_len_out = header_len;
    *total_len_out  = total_len;
    return NULL;
}

static const char *ipv4streamValidateIpv4HeaderChecksum(struct ip_hdr *iphdr, uint16_t header_len)
{
    uint16_t original_checksum = IPH_CHKSUM(iphdr);

    IPH_CHKSUM_SET(iphdr, 0);
    uint16_t expected_checksum = inet_chksum(iphdr, header_len);
    IPH_CHKSUM_SET(iphdr, original_checksum);

    if (original_checksum != expected_checksum)
    {
        return "invalid IPv4 header checksum";
    }

    return NULL;
}

static const char *ipv4streamValidateTcpChecksum(struct ip_hdr *iphdr, uint16_t header_len, uint16_t total_len)
{
    uint16_t transport_len = (uint16_t) (total_len - header_len);
    if (transport_len < TCP_HLEN)
    {
        return "TCP packet is smaller than the minimum header";
    }

    uint8_t        *transport = ((uint8_t *) iphdr) + header_len;
    struct tcp_hdr *tcphdr    = (struct tcp_hdr *) transport;
    uint16_t        tcp_hlen  = TCPH_HDRLEN_BYTES(tcphdr);

    if (tcp_hlen < TCP_HLEN || tcp_hlen > transport_len)
    {
        return "invalid TCP header length";
    }

    uint16_t original_checksum = tcphdr->chksum;
    tcphdr->chksum             = 0;
    uint16_t expected_checksum = calcGenericChecksum(
        transport, transport_len, ipv4streamChecksumPseudoHeader(iphdr, IP_PROTO_TCP, transport_len));
    tcphdr->chksum = original_checksum;

    if (original_checksum != expected_checksum)
    {
        return "invalid TCP checksum";
    }

    return NULL;
}

static const char *ipv4streamValidateUdpChecksum(struct ip_hdr *iphdr, uint16_t header_len, uint16_t total_len)
{
    uint16_t transport_len = (uint16_t) (total_len - header_len);
    if (transport_len < UDP_HLEN)
    {
        return "UDP packet is smaller than the minimum header";
    }

    uint8_t        *transport = ((uint8_t *) iphdr) + header_len;
    struct udp_hdr *udphdr    = (struct udp_hdr *) transport;
    uint16_t        udp_len   = lwip_ntohs(udphdr->len);

    if (udp_len < UDP_HLEN || udp_len > transport_len)
    {
        return "invalid UDP length";
    }

    if (udphdr->chksum == 0)
    {
        return NULL;
    }

    uint16_t original_checksum = udphdr->chksum;
    udphdr->chksum             = 0;
    uint16_t expected_checksum =
        calcGenericChecksum(transport, udp_len, ipv4streamChecksumPseudoHeader(iphdr, IP_PROTO_UDP, udp_len));
    udphdr->chksum = original_checksum;

    if (expected_checksum == 0)
    {
        expected_checksum = 0xFFFFU;
    }

    if (original_checksum != expected_checksum)
    {
        return "invalid UDP checksum";
    }

    return NULL;
}

static const char *ipv4streamValidateIcmpChecksum(struct ip_hdr *iphdr, uint16_t header_len, uint16_t total_len)
{
    uint16_t transport_len = (uint16_t) (total_len - header_len);
    if (transport_len < sizeof(struct icmp_hdr))
    {
        return "ICMP packet is smaller than the minimum header";
    }

    uint8_t         *transport = ((uint8_t *) iphdr) + header_len;
    struct icmp_hdr *icmphdr   = (struct icmp_hdr *) transport;

    uint16_t original_checksum = icmphdr->chksum;
    icmphdr->chksum            = 0;
    uint16_t expected_checksum = calcGenericChecksum(transport, transport_len, 0);
    icmphdr->chksum            = original_checksum;

    if (original_checksum != expected_checksum)
    {
        return "invalid ICMP checksum";
    }

    return NULL;
}

const char *ipv4streamValidationLevelName(ipv4stream_validation_level_t level)
{
    switch (level)
    {
    case kIpv4StreamValidationNone:
        return "none";
    case kIpv4StreamValidationLoose:
        return "loose";
    case kIpv4StreamValidationHard:
        return "hard";
    default:
        return "unknown";
    }
}

const char *ipv4streamValidatePacket(ipv4stream_validation_level_t level, sbuf_t *packet)
{
    assert(packet != NULL && ! sbufIsSplice(packet));
    assert(level >= kIpv4StreamValidationNone && level <= kIpv4StreamValidationHard);
    if (level == kIpv4StreamValidationNone)
        return NULL;

    struct ip_hdr *iphdr      = NULL;
    uint16_t       header_len = 0;
    uint16_t       total_len  = 0;
    const char    *reason     = ipv4streamValidateIpv4PacketHeader(packet, &iphdr, &header_len, &total_len);
    if (reason != NULL || level == kIpv4StreamValidationLoose)
        return reason;
    reason = ipv4streamValidateIpv4HeaderChecksum(iphdr, header_len);
    if (reason != NULL)
        return reason;
    const uint16_t frag_field = lwip_ntohs(IPH_OFFSET(iphdr));
    if ((frag_field & (IP_MF | IP_OFFMASK)) != 0)
        return NULL;
    switch (IPH_PROTO(iphdr))
    {
    case IP_PROTO_TCP:
        return ipv4streamValidateTcpChecksum(iphdr, header_len, total_len);
    case IP_PROTO_UDP:
        return ipv4streamValidateUdpChecksum(iphdr, header_len, total_len);
    case IP_PROTO_ICMP:
        return ipv4streamValidateIcmpChecksum(iphdr, header_len, total_len);
    default:
        return NULL;
    }
}

// Light, never-trusting structural check on a candidate IPv4 header (at least IP_HLEN bytes).
// This intentionally stays cheaper than the "loose" validation level: it only proves the head
// could be an IPv4 packet whose declared size is internally consistent and within the pipeline
// packet bound, so we know how many bytes a single packet would consume.
static inline bool ipv4streamIpv4HeaderLooksValid(const uint8_t *header, uint16_t *total_len_out)
{
    const uint8_t  version    = (uint8_t) (header[0] >> 4);
    const uint8_t  header_len = (uint8_t) ((header[0] & 0x0FU) * 4U);
    const uint16_t total_len  = (uint16_t) (((uint16_t) header[2] << 8) | (uint16_t) header[3]);

    *total_len_out = total_len;

    return version == 4 && header_len >= IP_HLEN && total_len >= header_len &&
           total_len <= (uint16_t) kMaxAllowedPacketLength;
}

// Drops leading bytes that cannot begin a valid IPv4 packet so the parser re-synchronizes on a
// garbage stream. It scans a bounded window for the next structurally-plausible IPv4 start and
// discards everything before it in one shot; if none is found it drops the inspected region while
// keeping the trailing bytes that might still be an incomplete header. Forward progress (>= 1
// byte) is always guaranteed, so no data pattern can stall the parser.
static void ipv4streamDropResyncBytes(buffer_stream_t *stream)
{
    const size_t buffered = bufferstreamGetBufLen(stream);
    const size_t window   = buffered < (size_t) kResyncScanWindow ? buffered : (size_t) kResyncScanWindow;

    uint8_t scan[kResyncScanWindow];
    bufferstreamViewBytesAt(stream, 0, scan, window);

    size_t found = 0; // offset 0 is the head we already rejected
    for (size_t i = 1; i + (size_t) IP_HLEN <= window; ++i)
    {
        uint16_t total_len;
        if (ipv4streamIpv4HeaderLooksValid(scan + i, &total_len))
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
bool ipv4streamIsForwardablePacket(const sbuf_t *packet)
{
    assert(packet != NULL && ! sbufIsSplice(packet));
    const uint32_t len = sbufGetLength(packet);

    if (UNLIKELY(len < IP_HLEN || len > (uint32_t) kMaxAllowedPacketLength))
    {
        return false;
    }

    uint16_t total_len;
    return LIKELY(ipv4streamIpv4HeaderLooksValid(sbufGetRawPtr(packet), &total_len) && total_len == len);
}

// Extracts exactly one IPv4 packet from the stream using the IPv4 total-length field as the frame
// size. Garbage is tolerated: a structurally-invalid head triggers re-synchronization, and a head
// that merely looks valid is trusted (worst case forwards a garbage-sized packet until the stream
// happens to realign). The stream is never trusted enough to read out of bounds or stall.
bool ipv4streamTryReadPacket(buffer_stream_t *stream, sbuf_t **packet_out)
{
    assert(stream != NULL && packet_out != NULL);
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
        if (LIKELY(ipv4streamIpv4HeaderLooksValid(header, &total_len)))
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
        ipv4streamDropResyncBytes(stream);
    }
}
