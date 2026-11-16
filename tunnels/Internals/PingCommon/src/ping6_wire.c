#include "PingCommon/ping6_wire.h"

/* Byte-oriented pseudo-header access also works with unaligned wire headers. */
static uint32_t ping6wirePseudoSeed(const uint8_t *ipv6, uint16_t message_length)
{
    uint32_t sum = (uint32_t) message_length + kPing6WireProtocol;
    if (ipv6 != NULL)
    {
        for (size_t i = 8; i < kPing6WireIpv6HeaderLength; i += 2)
        {
            sum += GET_BE16(ipv6 + i);
        }
    }
    return sum;
}

uint16_t ping6wireOverhead(const ping6_wire_config_t *config)
{
    assert(config != NULL && (config->mode == kPing6WireDirect || config->mode == kPing6WireIpv6InIpv4));
    return config->mode == kPing6WireIpv6InIpv4 ? kPing6WireIpv6InIpv4Overhead : kPing6WireEncapsulationOverhead;
}

uint8_t ping6wireCarrierProtocol(const ping6_wire_config_t *config)
{
    assert(config != NULL && (config->mode == kPing6WireDirect || config->mode == kPing6WireIpv6InIpv4));
    return config->mode == kPing6WireIpv6InIpv4 ? kPing6WireIpv6InIpv4Protocol : kPing6WireProtocol;
}

bool ping6wireEndpointIsAdmissible(const ip6_addr_t *address)
{
    assert(address != NULL);
    const uint8_t       *bytes    = (const uint8_t *) address->addr;
    static const uint8_t zero[16] = {0};
    if (bytes[0] == 0xff || memoryEqual(bytes, zero, 16))
    {
        return false;
    }
    if (memoryEqual(bytes, zero, 15) && bytes[15] == 1)
    {
        return false;
    }
    return ! (memoryEqual(bytes, zero, 10) && bytes[10] == 0xff && bytes[11] == 0xff);
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

const char *ping6wireEchoRequestError(const sbuf_t *buf, const ping6_wire_config_t *config)
{
    assert(buf != NULL && ! sbufIsSplice(buf) && config != NULL);
    ipv4_packet_view_t native = {0};
    const char        *error  = pingwireIpv4PacketErrorWithView(sbufGetRawPtr(buf), sbufGetLength(buf), &native);
    if (error != NULL)
    {
        return error;
    }
    if (native.fragmented)
    {
        return "fragmented IPv4 datagram requires adapter reassembly before Ping6";
    }
    if (! pingwireNativeShape(sbufGetRawPtr(buf) + native.transport_offset, native.transport_length, native.protocol))
    {
        return "invalid native TCP, UDP, or ICMP geometry";
    }
    const uint16_t overhead = ping6wireOverhead(config);
    if (sbufGetLength(buf) > (size_t) kMaxAllowedPacketLength - overhead)
    {
        return config->mode == kPing6WireDirect
                   ? "native IPv4 packet exceeds the 1491-byte direct limit (nine-byte Echo overhead)"
                   : "native IPv4 packet exceeds the 1451-byte ipv6-in-ipv4 limit (49-byte overhead)";
    }
    if (sbufGetHeadroom(buf) < overhead)
    {
        return config->mode == kPing6WireDirect ? "insufficient left headroom for nine-byte direct framing"
                                                : "insufficient left headroom for 49-byte ipv6-in-ipv4 framing";
    }
    return NULL;
}

const char *ping6wirePrepareEchoRequest(sbuf_t *buf, const ping6_wire_config_t *config)
{
    const char *error = ping6wireEchoRequestError(buf, config);
    if (error != NULL)
    {
        return error;
    }
    if (sbufGetRecalculateChecksum(buf) && ! calcFullPacketChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf)))
    {
        return "requested native IPv4/transport checksum repair failed";
    }
    sbufSetRecalculateChecksum(buf, false);
    return NULL;
}

bool ping6wireEchoRequestPreflight(const sbuf_t *buf, const ping6_wire_config_t *config)
{
    return buf != NULL && config != NULL && ping6wireEchoRequestError(buf, config) == NULL;
}

static void ping6wireWriteIpv6(uint8_t *ipv6, uint8_t traffic_class, uint16_t length, const void *source,
                               const void *destination)
{
    memoryZero(ipv6, kPing6WireIpv6HeaderLength);
    ipv6[0] = (uint8_t) (0x60U | (traffic_class >> 4U));
    ipv6[1] = (uint8_t) (traffic_class << 4U);
    PUT_BE16(ipv6 + 4, length);
    ipv6[6] = kPing6WireProtocol;
    ipv6[7] = 64;
    memoryCopy(ipv6 + 8, source, 16);
    memoryCopy(ipv6 + 24, destination, 16);
}

/* The caller has proved geometry; source/destination come from the actual header.
 * Direct mode deliberately never reads the unused config address fields. */
static void ping6wireRepairVisible(sbuf_t *buf, uint16_t echo_offset, bool has_ipv6)
{
    uint8_t       *packet = sbufGetMutablePtr(buf);
    const uint16_t length = (uint16_t) (sbufGetLength(buf) - echo_offset);
    const uint8_t *ipv6   = has_ipv6 ? packet + echo_offset - kPing6WireIpv6HeaderLength : NULL;
    uint8_t       *echo   = packet + echo_offset;
    PUT_BE16(echo + 2, 0);
    const uint16_t checksum = calcGenericChecksum(echo, length, ping6wirePseudoSeed(ipv6, length));
    memoryCopy(echo + 2, &checksum, sizeof(checksum));
    const bool repaired = calcIpv4HeaderChecksum(packet, sbufGetLength(buf));
    assert(repaired);
    discard repaired;
}

bool ping6wireBuildEchoRequest(sbuf_t *buf, const ping6_wire_config_t *config, uint16_t sequence)
{
    if (buf == NULL || config == NULL || ping6wirePrepareEchoRequest(buf, config) != NULL)
    {
        return false;
    }
    ipv4_packet_view_t native = {0};
    uint8_t           *packet = sbufGetMutablePtr(buf);
    const bool         parsed = ipv4packetviewParse(packet, sbufGetLength(buf), &native);
    assert(parsed);
    discard parsed;
    if (native.protocol == IPPROTO_TCP || native.protocol == IPPROTO_UDP)
    {
        const bool normalized = updateIpv4TransportChecksumAddresses(
            packet, sbufGetLength(buf), native.protocol, native.source_address, native.destination_address, 0, 0);
        assert(normalized);
        discard normalized;
    }
    const uint16_t overhead    = ping6wireOverhead(config);
    const uint16_t ipv6_length = (uint16_t) (overhead - kPing6WireEncapsulationOverhead);
    const uint16_t echo_offset = (uint16_t) (native.ip_header_length + ipv6_length);
    const uint16_t total       = (uint16_t) (native.ip_total_length + overhead);
    packet                     = sbufShiftLeft(buf, overhead);
    /* Header first, then body left one: the used end never moves and needs no tailroom. */
    memmove(packet, packet + overhead, native.ip_header_length);
    memmove(packet + echo_offset + kPing6WireIcmpHeaderLength,
            packet + overhead + native.ip_header_length,
            native.transport_length);
    packet[total - 1U] = native.protocol;
    if (ipv6_length != 0)
    {
        ping6wireWriteIpv6(packet + native.ip_header_length,
                           packet[1],
                           (uint16_t) (total - echo_offset),
                           config->local_ipv6.addr,
                           config->peer_ipv6.addr);
    }
    struct ip_hdr *ip = (struct ip_hdr *) packet;
    IPH_PROTO_SET(ip, ping6wireCarrierProtocol(config));
    IPH_LEN_SET(ip, lwip_htons(total));
    uint8_t *echo = packet + echo_offset;
    echo[0]       = kPing6WireEchoRequest;
    echo[1]       = 0;
    PUT_BE16(echo + 4, config->identifier);
    PUT_BE16(echo + 6, sequence);
    ping6wireRepairVisible(buf, echo_offset, ipv6_length != 0);
    return true;
}

/* All structural admission precedes checksum mutation. Replies have no native-body contract. */
static ping_wire_inbound_kind_t ping6wireInspect(const uint8_t *packet, uint32_t length,
                                                 const ping6_wire_config_t *config, ping6_wire_envelope_t *out,
                                                 bool checksums)
{
    if (out == NULL)
    {
        return kPingWireInboundMalformed;
    }
    memoryZero(out, sizeof(*out));
    if (config == NULL)
    {
        out->error_reason = "invalid Ping6 parser arguments";
        return kPingWireInboundMalformed;
    }
    ipv4_packet_view_t carrier = {0};
    out->error_reason          = pingwireIpv4PacketErrorWithView(packet, length, &carrier);
    if (out->error_reason != NULL)
    {
        return kPingWireInboundMalformed;
    }
    if (carrier.fragmented)
    {
        out->error_reason = "fragmented IPv4 datagram requires adapter reassembly before Ping6";
        return kPingWireInboundInvalidCarrier;
    }
    if (carrier.protocol != ping6wireCarrierProtocol(config))
    {
        if (checksums && calcGenericChecksum(packet, carrier.ip_header_length, 0) != 0)
        {
            out->error_reason = "invalid carrier IPv4 checksum";
            return kPingWireInboundMalformed;
        }
        return kPingWireInboundUnrelated;
    }
    if (length > kMaxAllowedPacketLength)
    {
        out->error_reason = "IPv4 packet exceeds maximum carrier size";
        return kPingWireInboundInvalidCarrier;
    }
    uint16_t       echo_offset = carrier.ip_header_length;
    const uint8_t *ipv6        = NULL;
    if (config->mode == kPing6WireIpv6InIpv4)
    {
        if (carrier.transport_length < kPing6WireIpv6HeaderLength)
        {
            out->error_reason = "truncated inner IPv6 header";
            return kPingWireInboundInvalidCarrier;
        }
        ipv6 = packet + carrier.ip_header_length;
        if ((ipv6[0] >> 4U) != 6 || ipv6[6] != kPing6WireProtocol)
        {
            out->error_reason = "inner IPv6 requires version 6 and immediate Next Header 58 (no extensions)";
            return kPingWireInboundInvalidCarrier;
        }
        if (GET_BE16(ipv6 + 4) != carrier.transport_length - kPing6WireIpv6HeaderLength)
        {
            out->error_reason = "inner IPv6 payload length does not match the outer IPv4 length";
            return kPingWireInboundInvalidCarrier;
        }
        if (! memoryEqual(ipv6 + 8, config->peer_ipv6.addr, 16) ||
            ! memoryEqual(ipv6 + 24, config->local_ipv6.addr, 16))
        {
            out->error_reason = "inner IPv6 source/destination do not match peer/local endpoints";
            return kPingWireInboundInvalidCarrier;
        }
        echo_offset += kPing6WireIpv6HeaderLength;
    }
    const uint16_t echo_length = (uint16_t) (length - echo_offset);
    if (echo_length < kPing6WireIcmpHeaderLength)
    {
        out->error_reason = "truncated Echo header";
        return kPingWireInboundInvalidCarrier;
    }
    const uint8_t *echo = packet + echo_offset;
    *out                = (ping6_wire_envelope_t) {
                       .icmp_payload        = echo + kPing6WireIcmpHeaderLength,
                       .source_ipv4         = carrier.source_address,
                       .destination_ipv4    = carrier.destination_address,
                       .total_length        = carrier.ip_total_length,
                       .icmp_payload_length = (uint16_t) (echo_length - kPing6WireIcmpHeaderLength),
                       .ip_header_length    = carrier.ip_header_length,
                       .echo_offset         = echo_offset,
                       .identifier          = GET_BE16(echo + 4),
                       .sequence            = GET_BE16(echo + 6),
                       .tos                 = packet[1],
                       .ttl                 = carrier.ttl,
                       .type                = echo[0],
                       .code                = echo[1],
    };
    if (out->code != 0 || (out->type != kPing6WireEchoRequest && out->type != kPing6WireEchoReply))
    {
        out->error_reason = "unsupported ICMPv6 type/code (Echo Request or Reply with code zero required)";
        return kPingWireInboundInvalidCarrier;
    }
    if (out->type == kPing6WireEchoRequest)
    {
        if (out->icmp_payload_length == 0)
        {
            out->error_reason = "Echo Request is missing its final protocol byte";
            return kPingWireInboundInvalidCarrier;
        }
        out->native_protocol    = packet[length - 1U];
        out->native_body_length = (uint16_t) (out->icmp_payload_length - 1U);
        if (! pingwireNativeShape(out->icmp_payload, out->native_body_length, out->native_protocol))
        {
            out->error_reason = "Echo Request has invalid native TCP, UDP, or ICMP geometry";
            return kPingWireInboundInvalidCarrier;
        }
    }
    if (checksums && calcGenericChecksum(packet, carrier.ip_header_length, 0) != 0)
    {
        out->error_reason = "invalid carrier IPv4 checksum";
        return kPingWireInboundMalformed;
    }
    if (checksums && calcGenericChecksum(echo, echo_length, ping6wirePseudoSeed(ipv6, echo_length)) != 0)
    {
        out->error_reason = "invalid Echo carrier checksum";
        return kPingWireInboundInvalidCarrier;
    }
    return out->type == kPing6WireEchoReply ? kPingWireInboundEchoReply : kPingWireInboundEchoRequest;
}

ping_wire_inbound_kind_t ping6wireParseInbound(const uint8_t *packet, uint32_t length,
                                               const ping6_wire_config_t *config, ping6_wire_envelope_t *out)
{
    return ping6wireInspect(packet, length, config, out, true);
}

bool ping6wireRecalculateCarrierChecksums(sbuf_t *buf, const ping6_wire_config_t *config)
{
    if (buf == NULL || config == NULL)
    {
        return false;
    }
    assert(! sbufIsSplice(buf));
    ping6_wire_envelope_t          view = {0};
    const ping_wire_inbound_kind_t kind =
        ping6wireInspect(sbufGetRawPtr(buf), sbufGetLength(buf), config, &view, false);
    if (kind != kPingWireInboundEchoRequest && kind != kPingWireInboundEchoReply)
    {
        return false;
    }
    ping6wireRepairVisible(buf, view.echo_offset, config->mode == kPing6WireIpv6InIpv4);
    return true;
}

bool ping6wireBuildEchoReply(sbuf_t *buf, const ping6_wire_config_t *config, const ping6_wire_envelope_t *request,
                             uint16_t ipv4_identification)
{
    if (buf == NULL || config == NULL || request == NULL || request->type != kPing6WireEchoRequest ||
        request->code != 0 || request->total_length != sbufGetLength(buf))
    {
        return false;
    }
    /* Revalidate the clone using the receiving endpoint's config, before any writes. */
    ping6_wire_envelope_t view = {0};
    if (ping6wireInspect(sbufGetRawPtr(buf), sbufGetLength(buf), config, &view, false) != kPingWireInboundEchoRequest ||
        view.ip_header_length != request->ip_header_length || view.echo_offset != request->echo_offset)
    {
        return false;
    }
    uint8_t *packet = sbufGetMutablePtr(buf);
    if (config->mode == kPing6WireIpv6InIpv4)
    {
        uint8_t      *ipv6          = packet + view.ip_header_length;
        const uint8_t traffic_class = (uint8_t) ((ipv6[0] << 4U) | (ipv6[1] >> 4U));
        uint8_t       addresses[32];
        memoryCopy(addresses, ipv6 + 8, sizeof(addresses));
        ping6wireWriteIpv6(ipv6,
                           traffic_class,
                           (uint16_t) (view.icmp_payload_length + kPing6WireIcmpHeaderLength),
                           addresses + 16,
                           addresses);
    }
    struct ip_hdr *ip = (struct ip_hdr *) packet;
    ip->src.addr      = view.destination_ipv4;
    ip->dest.addr     = view.source_ipv4;
    IPH_ID_SET(ip, lwip_htons(ipv4_identification));
    IPH_TTL_SET(ip, 64);
    IPH_TOS_SET(ip, view.tos);
    IPH_OFFSET_SET(ip, 0);
    packet[view.echo_offset] = kPing6WireEchoReply;
    ping6wireRepairVisible(buf, view.echo_offset, config->mode == kPing6WireIpv6InIpv4);
    sbufSetRecalculateChecksum(buf, false);
    return true;
}

bool ping6wireStripEchoRequest(sbuf_t *buf, const ping6_wire_envelope_t *request)
{
    if (buf == NULL || request == NULL || request->type != kPing6WireEchoRequest || request->code != 0 ||
        request->total_length != sbufGetLength(buf) || request->ip_header_length < IP_HLEN ||
        request->ip_header_length > IP_HLEN_MAX || request->icmp_payload_length == 0 ||
        request->icmp_payload_length != request->native_body_length + 1U ||
        (request->echo_offset != request->ip_header_length &&
         request->echo_offset != request->ip_header_length + kPing6WireIpv6HeaderLength) ||
        request->total_length != request->echo_offset + kPing6WireIcmpHeaderLength + request->icmp_payload_length)
    {
        return false;
    }
    /* The view aliases buf. Save needed values before either overlapping move. */
    const uint16_t header      = request->ip_header_length;
    const uint16_t echo_offset = request->echo_offset;
    const uint16_t overhead    = (uint16_t) (echo_offset - header + kPing6WireEncapsulationOverhead);
    const uint16_t body        = request->native_body_length;
    const uint16_t total       = (uint16_t) (request->total_length - overhead);
    const uint8_t  protocol    = request->native_protocol;
    const uint32_t source      = request->source_ipv4;
    const uint32_t destination = request->destination_ipv4;
    uint8_t       *packet      = sbufGetMutablePtr(buf);
    memmove(packet + header + overhead, packet + echo_offset + kPing6WireIcmpHeaderLength, body);
    memmove(packet + overhead, packet, header);
    packet            = sbufShiftRight(buf, overhead);
    struct ip_hdr *ip = (struct ip_hdr *) packet;
    IPH_PROTO_SET(ip, protocol);
    IPH_LEN_SET(ip, lwip_htons(total));
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
    {
        const bool restored = updateIpv4TransportChecksumAddresses(packet, total, protocol, 0, 0, source, destination);
        assert(restored);
        discard restored;
    }
    const bool repaired = calcIpv4HeaderChecksum(packet, total);
    assert(repaired);
    discard repaired;
    sbufSetRecalculateChecksum(buf, false);
    return true;
}
