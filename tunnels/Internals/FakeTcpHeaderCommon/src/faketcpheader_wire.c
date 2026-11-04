#include "FakeTcpHeaderCommon/faketcpheader_wire.h"

/* Every expected refusal precedes mutation. Offsets survive cursor changes;
 * only the IPv4 header moves, with memmove because actual IHL can exceed F+1. */

const char *faketcpheaderWireResultName(faketcpheader_wire_result_t result)
{
    switch (result)
    {
    case kFakeTcpHeaderWireOk:
        return "ok";
    case kFakeTcpHeaderWireMalformedNative:
        return "native packet has invalid IPv4 or known-protocol geometry";
    case kFakeTcpHeaderWireFragmented:
        return "fragmented IPv4 datagram requires upstream reassembly";
    case kFakeTcpHeaderWireOversizedNative:
        return "native packet exceeds the maximum size after fake TCP insertion";
    case kFakeTcpHeaderWireMissingHeadroom:
        return "insufficient left headroom for fake TCP and protocol byte";
    case kFakeTcpHeaderWireNativeRepairFailed:
        return "requested native checksum repair failed";
    case kFakeTcpHeaderWireMalformedCarrier:
        return "carrier is not one complete IPv4/TCP packet within the size limit";
    case kFakeTcpHeaderWireCarrierPorts:
        return "carrier ports do not match the configured mapping";
    case kFakeTcpHeaderWireCarrierChecksum:
        return "invalid visible IPv4 or fake TCP checksum";
    case kFakeTcpHeaderWireNativeFraming:
        return "carrier payload lacks a protocol byte or has malformed native geometry";
    }
    return "unknown result";
}

/* Match the complete, unfragmented IPv4 transport parser and checksum helper.
 * UDP may have IP payload bytes beyond its own declared datagram length. */
static bool faketcpheaderWireNativeShape(const uint8_t *native, uint16_t length, uint8_t protocol)
{
    if (protocol == IPPROTO_TCP)
    {
        if (length < TCP_HLEN)
        {
            return false;
        }
        const uint16_t header_length = (uint16_t) ((native[12] >> 4U) * 4U);
        return header_length >= TCP_HLEN && header_length <= length;
    }
    if (protocol == IPPROTO_ICMP)
    {
        return length >= sizeof(struct icmp_hdr);
    }
    if (protocol != IPPROTO_UDP)
    {
        return true;
    }
    if (length < UDP_HLEN)
    {
        return false;
    }
    const uint16_t datagram_length = GET_BE16(native + 4);
    return datagram_length >= UDP_HLEN && datagram_length <= length;
}

uint16_t faketcpheaderWirePortIndex(const faketcpheader_wire_config_t *config, const uint8_t *native,
                                    uint32_t native_length)
{
    assert(config->client_port_count >= 1);
    uint32_t hash = 0;
    if (! deviceFlowWorkerHash(native, native_length, &hash))
    {
        return 0;
    }
    return (uint16_t) (hash % config->client_port_count);
}

/* Sum of the TCP pseudo-header with the packet's actual current addresses. */
static uint32_t faketcpheaderWirePseudoHeaderSum(const uint8_t *ipv4, uint16_t segment_length)
{
    uint32_t sum = IP_PROTO_TCP + (uint32_t) segment_length;
    for (uint32_t offset = 12; offset < 20; offset += 2)
    {
        sum += GET_BE16(ipv4 + offset);
    }
    return sum;
}

void faketcpheaderWireInitSequences(faketcpheader_wire_config_t *config, atomic_u32_t *sequences)
{
    assert(config->client_port_count >= 1 && config->client_port_count <= kFakeTcpHeaderWireMaxClientPortCount);
    assert(config->sequence_mode >= kFakeTcpHeaderSequenceNumeric &&
           config->sequence_mode <= kFakeTcpHeaderSequenceRandomPort);
    if (config->sequence_mode == kFakeTcpHeaderSequenceRandomNode)
    {
        config->sequence = fastRand32();
    }
    if (! faketcpheaderWireNeedsSequences(config))
    {
        return;
    }
    assert(sequences != NULL);
    for (uint16_t i = 0; i < config->client_port_count; ++i)
    {
        const uint32_t seed =
            config->sequence_mode == kFakeTcpHeaderSequenceRandomPort ? fastRand32() : config->sequence;
        atomicStoreU32Relaxed(&sequences[i], seed);
    }
}

faketcpheader_wire_result_t faketcpheaderWireEncode(const faketcpheader_wire_config_t *config, atomic_u32_t *sequences,
                                                    faketcpheader_wire_side_t side, sbuf_t *buf)
{
    assert(side == kFakeTcpHeaderWireClient || side == kFakeTcpHeaderWireServer);
    assert(! sbufIsSplice(buf));
    assert(! faketcpheaderWireNeedsSequences(config) || sequences != NULL);

    const uint32_t     length             = sbufGetLength(buf);
    const uint16_t     overhead           = faketcpheaderWireOverhead(config);
    const uint16_t     fake_header_length = faketcpheaderWireTcpHeaderLength(config);
    uint8_t           *packet             = sbufGetMutablePtr(buf);
    ipv4_packet_view_t native             = {0};
    if (! ipv4packetviewParse(packet, length, &native) || native.ip_total_length != length)
    {
        return kFakeTcpHeaderWireMalformedNative;
    }
    if (native.fragmented)
    {
        return kFakeTcpHeaderWireFragmented;
    }
    if (! faketcpheaderWireNativeShape(packet + native.transport_offset, native.transport_length, native.protocol))
    {
        return kFakeTcpHeaderWireMalformedNative;
    }
    /* Widen before adding and before narrowing to the IPv4 total-length field. */
    const uint32_t total = length + (uint32_t) overhead;
    if (total > kFakeTcpHeaderWireMaxCarrierLength || total > UINT16_MAX)
    {
        return kFakeTcpHeaderWireOversizedNative;
    }
    if (sbufGetLeftCapacity(buf) < overhead)
    {
        return kFakeTcpHeaderWireMissingHeadroom;
    }
    const uint16_t index  = faketcpheaderWirePortIndex(config, packet, length);
    const uint16_t client = (uint16_t) (config->client_port + index);
    /* The shared repair API refuses without mutation. Nothing fallible follows. */
    if (sbufGetRecalculateChecksum(buf) && ! calcFullPacketChecksum(packet, length))
    {
        return kFakeTcpHeaderWireNativeRepairFailed;
    }

    if (native.protocol == IPPROTO_TCP || native.protocol == IPPROTO_UDP)
    {
        const bool normalized = updateIpv4TransportChecksumAddresses(
            packet, length, native.protocol, native.source_address, native.destination_address, 0, 0);
        assert(normalized);
        discard normalized;
    }

    sbufShiftLeft(buf, overhead);
    packet = sbufGetMutablePtr(buf);
    memmove(packet, packet + overhead, native.ip_header_length);
    struct ip_hdr *ip  = (struct ip_hdr *) packet;
    uint8_t       *tcp = packet + native.ip_header_length;
    memoryZero(tcp, overhead);
    IPH_LEN_SET(ip, lwip_htons((uint16_t) total));
    IPH_PROTO_SET(ip, IP_PROTO_TCP);

    PUT_BE16(tcp, side == kFakeTcpHeaderWireClient ? client : config->server_port);
    PUT_BE16(tcp + 2, side == kFakeTcpHeaderWireClient ? config->server_port : client);
    /* All refusals precede this reservation. Only the fake TCP payload occupies
     * sequence space: the protocol byte plus the original IP payload. */
    uint32_t sequence = config->sequence;
    if (config->increment_sequence)
    {
        sequence = atomicAddU32Explicit(&sequences[index],
                                        (uint32_t) native.transport_length + kFakeTcpHeaderWireProtocolLength,
                                        memory_order_relaxed);
    }
    else if (config->sequence_mode == kFakeTcpHeaderSequenceRandomPort)
    {
        sequence = atomicLoadU32Relaxed(&sequences[index]);
    }
    PUT_BE32(tcp + 4, sequence);
    PUT_BE32(tcp + 8, config->acknowledgment);
    tcp[12] = (uint8_t) ((fake_header_length / 4U) << 4U);
    tcp[13] = kFakeTcpHeaderWireTcpFlags;
    PUT_BE16(tcp + 14, config->window);
    PUT_BE16(tcp + 18, config->urgent_pointer);
    memoryCopy(tcp + kFakeTcpHeaderWireTcpHeaderLength, config->options, config->options_length);
    tcp[fake_header_length] = native.protocol;

    /* Only the exposed IP/fake TCP checksums are recalculated here. */
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
    assert(side == kFakeTcpHeaderWireClient || side == kFakeTcpHeaderWireServer);
    assert(! sbufIsSplice(buf));

    const uint32_t     length  = sbufGetLength(buf);
    uint8_t           *packet  = sbufGetMutablePtr(buf);
    ipv4_packet_view_t carrier = {0};
    if (length > kFakeTcpHeaderWireMaxCarrierLength || ! ipv4packetviewParse(packet, length, &carrier) ||
        carrier.ip_total_length != length)
    {
        return kFakeTcpHeaderWireMalformedCarrier;
    }
    if (carrier.fragmented)
    {
        return kFakeTcpHeaderWireFragmented;
    }
    if (! ipv4packetviewParseTcp(packet, length, &carrier))
    {
        return kFakeTcpHeaderWireMalformedCarrier;
    }
    if (! faketcpheaderWirePortsMatch(config, side, carrier.source_port, carrier.destination_port))
    {
        return kFakeTcpHeaderWireCarrierPorts;
    }
    if (carrier.payload_length < kFakeTcpHeaderWireProtocolLength)
    {
        return kFakeTcpHeaderWireNativeFraming;
    }
    const uint8_t protocol = packet[carrier.payload_offset];
    if (! faketcpheaderWireNativeShape(packet + carrier.payload_offset + kFakeTcpHeaderWireProtocolLength,
                                       (uint16_t) (carrier.payload_length - kFakeTcpHeaderWireProtocolLength),
                                       protocol))
    {
        return kFakeTcpHeaderWireNativeFraming;
    }
    /* A request makes only the exposed checksums non-authoritative. */
    if (! sbufGetRecalculateChecksum(buf) &&
        (calcGenericChecksum(packet, carrier.ip_header_length, 0) != 0 ||
         calcGenericChecksum(packet + carrier.transport_offset,
                             carrier.transport_length,
                             faketcpheaderWirePseudoHeaderSum(packet, carrier.transport_length)) != 0))
    {
        return kFakeTcpHeaderWireCarrierChecksum;
    }

    const uint16_t overhead = (uint16_t) (carrier.transport_header_length + kFakeTcpHeaderWireProtocolLength);
    const uint16_t total    = (uint16_t) (length - overhead);
    memmove(packet + overhead, packet, carrier.ip_header_length);
    sbufShiftRight(buf, overhead);
    packet            = sbufGetMutablePtr(buf);
    struct ip_hdr *ip = (struct ip_hdr *) packet;
    IPH_PROTO_SET(ip, protocol);
    IPH_LEN_SET(ip, lwip_htons(total));
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
    {
        const bool restored = updateIpv4TransportChecksumAddresses(
            packet, total, protocol, 0, 0, carrier.source_address, carrier.destination_address);
        assert(restored);
        discard restored;
    }
    const bool checksummed = calcIpv4HeaderChecksum(packet, total);
    assert(checksummed);
    discard checksummed;
    sbufSetRecalculateChecksum(buf, false);
    return kFakeTcpHeaderWireOk;
}
