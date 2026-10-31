#include "FakeTcpHeaderCommon/faketcpheader_wire.h"

/*
 * Every refusal is decided before the first write: encode preflights framing,
 * size and headroom before honoring a repair request, and the checksum API
 * refuses without modifying the packet. The repair request is read, never
 * taken, so a refused packet keeps its intent for the caller.
 */

enum
{
    kFakeTcpHeaderWireTosEcnMask = 0x03,
};

const char *faketcpheaderWireResultName(faketcpheader_wire_result_t result)
{
    switch (result)
    {
    case kFakeTcpHeaderWireOk:
        return "ok";
    case kFakeTcpHeaderWireMalformedInner:
        return "inner packet is not one complete IPv4 packet";
    case kFakeTcpHeaderWireOversizedInner:
        return "inner packet exceeds the maximum inner size";
    case kFakeTcpHeaderWireMissingHeadroom:
        return "insufficient left headroom for the carrier headers";
    case kFakeTcpHeaderWireInnerRepairFailed:
        return "requested inner checksum repair failed";
    case kFakeTcpHeaderWireMalformedCarrier:
        return "carrier is not one complete unfragmented IPv4/TCP packet";
    case kFakeTcpHeaderWireCarrierPorts:
        return "carrier ports do not match the configured mapping";
    case kFakeTcpHeaderWireOuterChecksum:
        return "invalid outer IPv4 or TCP checksum";
    case kFakeTcpHeaderWireInnerFraming:
        return "carrier payload is not one complete IPv4 packet";
    }
    return "unknown result";
}

static bool faketcpheaderWireIsExactIpv4(const uint8_t *packet, uint32_t length)
{
    ipv4_packet_view_t view = {0};
    return ipv4packetviewParse(packet, length, &view) && view.ip_total_length == length;
}

uint16_t faketcpheaderWirePortIndex(const faketcpheader_wire_config_t *config, const uint8_t *inner,
                                    uint32_t inner_length)
{
    assert(config->client_port_count >= 1);
    uint32_t hash = 0;
    if (! deviceFlowWorkerHash(inner, inner_length, &hash))
    {
        return 0;
    }
    return (uint16_t) (hash % config->client_port_count);
}

/* Sum of the TCP pseudo-header (addresses, protocol, segment length) as the checksum seed. */
static uint32_t faketcpheaderWirePseudoHeaderSum(const uint8_t *ipv4, uint16_t segment_length)
{
    uint32_t sum = IP_PROTO_TCP + (uint32_t) segment_length;
    for (uint32_t offset = 12; offset < 20; offset += 2)
    {
        sum += GET_BE16(ipv4 + offset);
    }
    return sum;
}

faketcpheader_wire_result_t faketcpheaderWireEncode(const faketcpheader_wire_config_t *config,
                                                    faketcpheader_wire_side_t side, sbuf_t *buf)
{
    assert(! sbufIsSplice(buf));

    const uint32_t inner_length = sbufGetLength(buf);
    const uint16_t overhead     = faketcpheaderWireOverhead(config);
    if (! faketcpheaderWireIsExactIpv4(sbufGetRawPtr(buf), inner_length))
    {
        return kFakeTcpHeaderWireMalformedInner;
    }
    if (inner_length > faketcpheaderWireMaxInnerLength(config))
    {
        return kFakeTcpHeaderWireOversizedInner;
    }
    if (sbufGetLeftCapacity(buf) < overhead)
    {
        return kFakeTcpHeaderWireMissingHeadroom;
    }
    /* Without a request the inner checksums are carried unchanged, valid or not. */
    if (sbufGetRecalculateChecksum(buf) && ! calcFullPacketChecksum(sbufGetMutablePtr(buf), inner_length))
    {
        return kFakeTcpHeaderWireInnerRepairFailed;
    }

    const uint16_t index      = faketcpheaderWirePortIndex(config, sbufGetRawPtr(buf), inner_length);
    const uint16_t client     = (uint16_t) (config->client_port + index);
    const uint16_t total      = (uint16_t) (overhead + inner_length);
    const uint8_t  inner_tos  = IPH_TOS((const struct ip_hdr *) sbufGetRawPtr(buf));
    const uint32_t inner_src  = ((const struct ip_hdr *) sbufGetRawPtr(buf))->src.addr;
    const uint32_t inner_dest = ((const struct ip_hdr *) sbufGetRawPtr(buf))->dest.addr;

    sbufShiftLeft(buf, overhead);
    uint8_t       *packet = sbufGetMutablePtr(buf);
    struct ip_hdr *ip     = (struct ip_hdr *) packet;
    uint8_t       *tcp    = packet + kFakeTcpHeaderWireIpv4HeaderLength;

    memoryZero(packet, overhead);
    IPH_VHL_SET(ip, 4, kFakeTcpHeaderWireIpv4HeaderLength / 4U);
    /* DSCP follows the inner packet; ECN is Not-ECT because decode cannot propagate CE. */
    IPH_TOS_SET(ip, (uint8_t) (inner_tos & ~kFakeTcpHeaderWireTosEcnMask));
    IPH_LEN_SET(ip, lwip_htons(total));
    IPH_ID_SET(ip, 0);
    IPH_OFFSET_SET(ip, lwip_htons(IP_DF));
    IPH_TTL_SET(ip, kFakeTcpHeaderWireTtl);
    IPH_PROTO_SET(ip, IP_PROTO_TCP);
    ip->src.addr  = inner_src;
    ip->dest.addr = inner_dest;

    PUT_BE16(tcp, side == kFakeTcpHeaderWireClient ? client : config->server_port);
    PUT_BE16(tcp + 2, side == kFakeTcpHeaderWireClient ? config->server_port : client);
    PUT_BE32(tcp + 4, config->sequence);
    PUT_BE32(tcp + 8, config->acknowledgment);
    tcp[12] = (uint8_t) (((kFakeTcpHeaderWireTcpHeaderLength + config->options_length) / 4U) << 4U);
    tcp[13] = kFakeTcpHeaderWireTcpFlags;
    PUT_BE16(tcp + 14, config->window);
    PUT_BE16(tcp + 18, config->urgent_pointer);
    memoryCopy(tcp + kFakeTcpHeaderWireTcpHeaderLength, config->options, config->options_length);

    /* Computes the outer IPv4 header and TCP checksums; the inner packet is TCP payload. */
    const bool checksummed = calcFullPacketChecksum(packet, total);
    assert(checksummed);
    discard checksummed;

    sbufSetRecalculateChecksum(buf, false);
    return kFakeTcpHeaderWireOk;
}

static bool faketcpheaderWirePortsMatch(const faketcpheader_wire_config_t *config, faketcpheader_wire_side_t side,
                                        uint16_t source_port, uint16_t destination_port)
{
    const uint16_t server_port = side == kFakeTcpHeaderWireClient ? source_port : destination_port;
    const uint16_t client_port = side == kFakeTcpHeaderWireClient ? destination_port : source_port;
    return server_port == config->server_port && client_port >= config->client_port &&
           (uint32_t) client_port < (uint32_t) config->client_port + config->client_port_count;
}

faketcpheader_wire_result_t faketcpheaderWireDecode(const faketcpheader_wire_config_t *config,
                                                    faketcpheader_wire_side_t side, sbuf_t *buf)
{
    assert(! sbufIsSplice(buf));

    const uint32_t     length = sbufGetLength(buf);
    const uint8_t     *packet = sbufGetRawPtr(buf);
    ipv4_packet_view_t outer  = {0};
    if (length > kFakeTcpHeaderWireMaxCarrierLength || ! ipv4packetviewParseTcp(packet, length, &outer) ||
        outer.ip_total_length != length || outer.fragmented)
    {
        return kFakeTcpHeaderWireMalformedCarrier;
    }
    if (! faketcpheaderWirePortsMatch(config, side, outer.source_port, outer.destination_port))
    {
        return kFakeTcpHeaderWireCarrierPorts;
    }
    /* A pending repair request means the outer checksums are not yet authoritative. */
    if (! sbufGetRecalculateChecksum(buf) &&
        (calcGenericChecksum(packet, outer.ip_header_length, 0) != 0 ||
         calcGenericChecksum(packet + outer.transport_offset,
                             outer.transport_length,
                             faketcpheaderWirePseudoHeaderSum(packet, outer.transport_length)) != 0))
    {
        return kFakeTcpHeaderWireOuterChecksum;
    }
    if (! faketcpheaderWireIsExactIpv4(packet + outer.payload_offset, outer.payload_length))
    {
        return kFakeTcpHeaderWireInnerFraming;
    }

    sbufShiftRight(buf, outer.payload_offset);
    sbufSetRecalculateChecksum(buf, false);
    return kFakeTcpHeaderWireOk;
}
