#include "PingCommon/ping6_wire.h"

static uint32_t ping6wireSumIpv6Address(const ip6_addr_t *address, uint32_t sum)
{
    const uint8_t *bytes = (const uint8_t *) address->addr;
    for (size_t i = 0; i < sizeof(address->addr); i += 2)
    {
        sum += ((uint32_t) bytes[i] << 8U) | bytes[i + 1U];
    }
    return sum;
}

/* The sum commutes: swapping source and destination gives the same checksum, so it cannot prove a direction. */
static uint32_t ping6wirePseudoSeed(const ip6_addr_t *source, const ip6_addr_t *destination, uint32_t length)
{
    uint32_t sum = ping6wireSumIpv6Address(source, 0);
    sum          = ping6wireSumIpv6Address(destination, sum);
    sum += (length >> 16U) & UINT16_MAX;
    sum += length & UINT16_MAX;
    sum += kPing6WireProtocol;
    return sum;
}

static uint16_t ping6wireChecksum(const uint8_t *message, uint16_t length, const ip6_addr_t *source,
                                  const ip6_addr_t *destination)
{
    return calcGenericChecksum(message, length, ping6wirePseudoSeed(source, destination, length));
}

void ping6wireIpv4MappedAddress(uint32_t ipv4, ip6_addr_t *address_out)
{
    assert(address_out != NULL);
    memoryZero(address_out, sizeof(*address_out));
    address_out->addr[2] = lwip_htonl(UINT16_MAX);
    address_out->addr[3] = ipv4;
}

bool ping6wireParseIpv4Text(const char *text, uint32_t *ipv4_out)
{
    assert(text != NULL && ipv4_out != NULL);

    /* lwIP alone also accepts hex, octal, short forms and trailing text; require one plain dotted quad. */
    uint8_t bytes[4];
    for (size_t field = 0; field < sizeof(bytes); ++field)
    {
        const char *first     = text;
        const char  separator = field + 1U < sizeof(bytes) ? '.' : '\0';
        uint32_t    value     = 0;
        while (*text >= '0' && *text <= '9' && text - first < 3)
        {
            value = value * 10U + (uint32_t) (*text++ - '0');
        }
        if (text == first || value > UINT8_MAX || (text - first > 1 && *first == '0') || *text != separator)
        {
            return false;
        }
        bytes[field] = (uint8_t) value;
        if (separator != '\0')
        {
            ++text;
        }
    }
    memoryCopy(ipv4_out, bytes, sizeof(bytes));
    return true;
}

bool ping6wireParseIpv6Text(const char *text, ip6_addr_t *address_out)
{
    assert(text != NULL && address_out != NULL);

    /* Keep bare-address syntax and strict decimal IPv4 tails consistent across platforms. */
    const char *group = text;
    for (const char *c = text; *c != '\0'; ++c)
    {
        if (*c == ':')
        {
            group = c + 1;
        }
        else if (*c == '.')
        {
            uint32_t embedded_ipv4;
            if (! ping6wireParseIpv4Text(group, &embedded_ipv4))
            {
                return false;
            }
            break;
        }
        else if (! ((*c >= '0' && *c <= '9') || (*c >= 'a' && *c <= 'f') || (*c >= 'A' && *c <= 'F')) || c - group >= 4)
        {
            return false;
        }
    }
    /* Native parsing validates colon grammar and handles compressed embedded-IPv4 forms. */
    struct in6_addr parsed;
    if (inet_pton(AF_INET6, text, &parsed) != 1)
    {
        return false;
    }

    memoryZero(address_out, sizeof(*address_out));
    memoryCopy(address_out->addr, &parsed, sizeof(address_out->addr));
    return true;
}

bool ping6wireEchoRequestPreflight(const sbuf_t *buf)
{
    return buf != NULL && pingwireIsExactIpv4Packet(sbufGetRawPtr(buf), sbufGetLength(buf)) &&
           sbufGetLength(buf) <= kPing6WireMaxInnerPacketLength &&
           sbufGetHeadroom(buf) >= kPing6WireEncapsulationOverhead;
}

bool ping6wireBuildEchoRequest(sbuf_t *buf, const ping6_wire_config_t *config, uint16_t sequence)
{
    if (config == NULL || ! ping6wireEchoRequestPreflight(buf))
    {
        return false;
    }

    const uint32_t total_length = sbufGetLength(buf) + kPing6WireEncapsulationOverhead;
    assert(total_length <= kMaxAllowedPacketLength);
    sbufShiftLeft(buf, kPing6WireEncapsulationOverhead);

    uint8_t               *packet = sbufGetMutablePtr(buf);
    struct ip_hdr         *ip     = (struct ip_hdr *) packet;
    struct icmp6_echo_hdr *icmp   = (struct icmp6_echo_hdr *) (packet + kPing6WireIpv4HeaderLength);

    memoryZero(packet, kPing6WireEncapsulationOverhead);
    IPH_VHL_SET(ip, 4, kPing6WireIpv4HeaderLength / 4U);
    IPH_TOS_SET(ip, config->tos);
    IPH_LEN_SET(ip, lwip_htons((uint16_t) total_length));
    IPH_ID_SET(ip, 0);
    IPH_OFFSET_SET(ip, lwip_htons(IP_DF));
    IPH_TTL_SET(ip, config->ttl);
    IPH_PROTO_SET(ip, kPing6WireProtocol);
    ip->src.addr  = config->local_ipv4;
    ip->dest.addr = config->peer_ipv4;

    icmp->type   = kPing6WireEchoRequest;
    icmp->code   = 0;
    icmp->id     = lwip_htons(config->identifier);
    icmp->seqno  = lwip_htons(sequence);
    icmp->chksum = ping6wireChecksum((const uint8_t *) icmp,
                                     (uint16_t) (total_length - kPing6WireIpv4HeaderLength),
                                     &config->local_ipv6,
                                     &config->peer_ipv6);

    return calcIpv4HeaderChecksum(packet, total_length);
}

static const char *ping6wireOuterIpv4Error(const uint8_t *packet, uint32_t length, ipv4_packet_view_t *view_out)
{
    const char *error = pingwireIpv4PacketErrorWithView(packet, length, view_out);
    if (error != NULL)
    {
        return error;
    }
    return inet_chksum(packet, view_out->ip_header_length) == 0 ? NULL : "invalid outer IPv4 checksum";
}

ping_wire_inbound_kind_t ping6wireParseInbound(const uint8_t *packet, uint32_t length,
                                               const ping6_wire_config_t *config, ping6_wire_envelope_t *envelope_out)
{
    if (envelope_out != NULL)
    {
        memoryZero(envelope_out, sizeof(*envelope_out));
    }
    if (config == NULL || packet == NULL || envelope_out == NULL)
    {
        if (envelope_out != NULL)
        {
            envelope_out->error_reason = "invalid Ping6 parser arguments";
        }
        return kPingWireInboundMalformed;
    }

    ipv4_packet_view_t outer   = {0};
    envelope_out->error_reason = ping6wireOuterIpv4Error(packet, length, &outer);
    if (envelope_out->error_reason != NULL)
    {
        return kPingWireInboundMalformed;
    }
    if (outer.source_address != config->peer_ipv4 || outer.destination_address != config->local_ipv4 ||
        outer.protocol != kPing6WireProtocol)
    {
        return kPingWireInboundUnrelated;
    }
    if (length > kMaxAllowedPacketLength)
    {
        envelope_out->error_reason = "outer IPv4 packet exceeds maximum carrier size";
        return kPingWireInboundInvalidCarrier;
    }
    if (outer.ip_header_length != kPing6WireIpv4HeaderLength)
    {
        envelope_out->error_reason = "outer IPv4 header options are unsupported for Ping6 carriers";
        return kPingWireInboundInvalidCarrier;
    }
    if (outer.fragmented)
    {
        envelope_out->error_reason = "fragmented outer IPv4 Ping6 carrier";
        return kPingWireInboundInvalidCarrier;
    }
    if (outer.transport_length < kPing6WireIcmpHeaderLength)
    {
        envelope_out->error_reason = "truncated ICMPv6 Echo header";
        return kPingWireInboundInvalidCarrier;
    }

    const uint8_t               *icmp_bytes = packet + outer.transport_offset;
    const struct icmp6_echo_hdr *icmp       = (const struct icmp6_echo_hdr *) icmp_bytes;
    if (ping6wireChecksum(icmp_bytes, outer.transport_length, &config->peer_ipv6, &config->local_ipv6) != 0)
    {
        envelope_out->error_reason = "invalid ICMPv6 checksum";
        return kPingWireInboundInvalidCarrier;
    }

    *envelope_out = (ping6_wire_envelope_t) {
        .icmp_payload        = icmp_bytes + kPing6WireIcmpHeaderLength,
        .inner_ipv4          = icmp_bytes + kPing6WireIcmpHeaderLength,
        .source_ipv4         = outer.source_address,
        .destination_ipv4    = outer.destination_address,
        .total_length        = outer.ip_total_length,
        .icmp_payload_length = (uint16_t) (outer.transport_length - kPing6WireIcmpHeaderLength),
        .inner_ipv4_length   = (uint16_t) (outer.transport_length - kPing6WireIcmpHeaderLength),
        .identifier          = lwip_ntohs(icmp->id),
        .sequence            = lwip_ntohs(icmp->seqno),
        .tos                 = IPH_TOS((const struct ip_hdr *) packet),
        .ttl                 = outer.ttl,
        .type                = icmp->type,
        .code                = icmp->code,
    };

    if (icmp->code != 0)
    {
        envelope_out->error_reason = "unsupported ICMPv6 Echo code (zero required)";
        return kPingWireInboundInvalidCarrier;
    }
    if (icmp->type == kPing6WireEchoRequest)
    {
        if (! pingwireIsExactIpv4Packet(envelope_out->inner_ipv4, envelope_out->inner_ipv4_length))
        {
            envelope_out->error_reason = "ICMPv6 Echo Request payload is not one complete inner IPv4 packet";
            return kPingWireInboundInvalidCarrier;
        }
        return kPingWireInboundEchoRequest;
    }
    if (icmp->type == kPing6WireEchoReply)
    {
        return kPingWireInboundEchoReply;
    }

    envelope_out->error_reason = "unsupported ICMPv6 type (Echo Request or Echo Reply required)";
    return kPingWireInboundInvalidCarrier;
}

bool ping6wireBuildEchoReply(sbuf_t *buf, const ping6_wire_config_t *config, const ping6_wire_envelope_t *request,
                             uint16_t ipv4_identification)
{
    if (buf == NULL || config == NULL || request == NULL || request->type != kPing6WireEchoRequest ||
        request->code != 0 || request->total_length != sbufGetLength(buf) ||
        request->total_length < kPing6WireEncapsulationOverhead)
    {
        return false;
    }

    uint8_t               *packet = sbufGetMutablePtr(buf);
    struct ip_hdr         *ip     = (struct ip_hdr *) packet;
    struct icmp6_echo_hdr *icmp   = (struct icmp6_echo_hdr *) (packet + kPing6WireIpv4HeaderLength);
    if (! pingwireIsExactIpv4Packet(packet, sbufGetLength(buf)) || IPH_HL_BYTES(ip) != kPing6WireIpv4HeaderLength ||
        IPH_PROTO(ip) != kPing6WireProtocol)
    {
        return false;
    }

    IPH_VHL_SET(ip, 4, kPing6WireIpv4HeaderLength / 4U);
    IPH_TOS_SET(ip, request->tos);
    IPH_LEN_SET(ip, lwip_htons(request->total_length));
    IPH_ID_SET(ip, lwip_htons(ipv4_identification));
    IPH_OFFSET_SET(ip, 0);
    IPH_TTL_SET(ip, config->ttl);
    IPH_PROTO_SET(ip, kPing6WireProtocol);
    ip->src.addr  = config->local_ipv4;
    ip->dest.addr = config->peer_ipv4;

    icmp->type   = kPing6WireEchoReply;
    icmp->code   = 0;
    icmp->chksum = 0;
    icmp->chksum = ping6wireChecksum((const uint8_t *) icmp,
                                     (uint16_t) (request->total_length - kPing6WireIpv4HeaderLength),
                                     &config->local_ipv6,
                                     &config->peer_ipv6);
    return calcIpv4HeaderChecksum(packet, request->total_length);
}

bool ping6wireStripEchoRequest(sbuf_t *buf, const ping6_wire_envelope_t *request)
{
    if (buf == NULL || request == NULL || request->type != kPing6WireEchoRequest || request->code != 0 ||
        request->total_length != sbufGetLength(buf) || request->inner_ipv4_length == 0 ||
        request->inner_ipv4_length != request->icmp_payload_length ||
        request->total_length != (uint16_t) (kPing6WireEncapsulationOverhead + request->inner_ipv4_length))
    {
        return false;
    }

    sbufShiftRight(buf, kPing6WireEncapsulationOverhead);
    sbufSetLength(buf, request->inner_ipv4_length);
    return true;
}

bool ping6wireRecalculateCarrierChecksums(sbuf_t *buf, const ip6_addr_t *source, const ip6_addr_t *destination)
{
    if (buf == NULL || source == NULL || destination == NULL || sbufGetLength(buf) > kMaxAllowedPacketLength)
    {
        return false;
    }

    uint8_t           *packet = sbufGetMutablePtr(buf);
    ipv4_packet_view_t view   = {0};
    if (! ipv4packetviewParse(packet, sbufGetLength(buf), &view) || view.ip_total_length != sbufGetLength(buf) ||
        view.ip_header_length != kPing6WireIpv4HeaderLength || view.fragmented || view.protocol != kPing6WireProtocol ||
        view.transport_length < kPing6WireIcmpHeaderLength)
    {
        return false;
    }

    struct icmp6_echo_hdr *icmp = (struct icmp6_echo_hdr *) (packet + view.transport_offset);
    icmp->chksum                = 0;
    icmp->chksum                = ping6wireChecksum((const uint8_t *) icmp, view.transport_length, source, destination);
    return calcIpv4HeaderChecksum(packet, view.ip_total_length);
}
