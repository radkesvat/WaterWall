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

/* IPv6 addresses supply checksum context only; never derive them from IPv4. */
static uint32_t ping6wirePacketSeed(const uint8_t *packet, uint32_t length, const ping6_wire_config_t *config,
                                    bool encoding)
{
    ipv4_packet_view_t view = {0};
    if (! ipv4packetviewParse(packet, length, &view) || view.ip_total_length != length)
    {
        return 0; /* Shared admission reports malformed geometry without mutation. */
    }
    const uint32_t message_length =
        (uint32_t) view.transport_length + (encoding ? kPing6WireEncapsulationOverhead : 0U);
    return ping6wirePseudoSeed(&config->local_ipv6, &config->peer_ipv6, message_length);
}

bool ping6wireEchoRequestPreflight(const sbuf_t *buf)
{
    return pingwireEchoRequestPreflight(buf);
}

bool ping6wireBuildEchoRequest(sbuf_t *buf, const ping6_wire_config_t *config, uint16_t sequence)
{
    if (config == NULL || buf == NULL)
    {
        return false;
    }
    const uint32_t seed = ping6wirePacketSeed(sbufGetRawPtr(buf), sbufGetLength(buf), config, true);
    return pingwireBuildRequest(buf, config->identifier, sequence, kPing6WireProtocol, kPing6WireEchoRequest, seed);
}

ping_wire_inbound_kind_t ping6wireParseInbound(const uint8_t *packet, uint32_t length,
                                               const ping6_wire_config_t *config, ping6_wire_envelope_t *envelope_out)
{
    if (config == NULL)
    {
        if (envelope_out != NULL)
        {
            memoryZero(envelope_out, sizeof(*envelope_out));
            envelope_out->error_reason = "invalid Ping6 parser arguments";
        }
        return kPingWireInboundMalformed;
    }
    const uint32_t seed = ping6wirePacketSeed(packet, length, config, false);
    return pingwireParseEcho(
        packet, length, kPing6WireProtocol, kPing6WireEchoRequest, kPing6WireEchoReply, seed, envelope_out);
}

bool ping6wireBuildEchoReply(sbuf_t *buf, const ping6_wire_config_t *config, const ping6_wire_envelope_t *request,
                             uint16_t ipv4_identification)
{
    if (config == NULL || buf == NULL)
    {
        return false;
    }
    const uint32_t seed = ping6wirePacketSeed(sbufGetRawPtr(buf), sbufGetLength(buf), config, false);
    return pingwireBuildReply(
        buf, request, ipv4_identification, kPing6WireProtocol, kPing6WireEchoRequest, kPing6WireEchoReply, seed);
}

bool ping6wireStripEchoRequest(sbuf_t *buf, const ping6_wire_envelope_t *request)
{
    return pingwireStripRequest(buf, request, kPing6WireEchoRequest);
}

bool ping6wireRecalculateCarrierChecksums(sbuf_t *buf, const ip6_addr_t *source, const ip6_addr_t *destination)
{
    if (buf == NULL || source == NULL || destination == NULL)
    {
        return false;
    }
    ipv4_packet_view_t view = {0};
    if (! ipv4packetviewParse(sbufGetRawPtr(buf), sbufGetLength(buf), &view))
    {
        return false;
    }
    return pingwireRecalculateEchoChecksums(
        buf, kPing6WireProtocol, ping6wirePseudoSeed(source, destination, view.transport_length));
}
