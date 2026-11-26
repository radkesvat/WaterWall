#include "PingCommon/ping_ipv4.h"

#include "PingCommon/ping_wire.h"

_Static_assert(kPingIpv4Overhead == 10, "Ping IPv4 transmit padding changed unexpectedly");

static const char *pingipv4PacketError(const uint8_t *packet, uint32_t length, ipv4_packet_view_t *view)
{
    const char *error = pingwireIpv4PacketErrorWithView(packet, length, view);
    if (error != NULL)
    {
        return error;
    }

    for (size_t offset = IP_HLEN; offset < view->ip_header_length;)
    {
        const uint8_t kind = packet[offset];
        if (kind == 0) /* End of options. */
        {
            break;
        }
        if (kind == 1) /* NOP occupies one byte. */
        {
            ++offset;
            continue;
        }
        if (kind == 131 || kind == 137) /* Loose or strict source route. */
        {
            return "IPv4 source routing is unsupported by Ping";
        }
        const size_t remaining = view->ip_header_length - offset;
        if (remaining < 2)
        {
            return "truncated IPv4 option";
        }
        const uint8_t option_length = packet[offset + 1];
        if (option_length < 2 || option_length > remaining)
        {
            return "invalid IPv4 option length";
        }
        offset += option_length;
    }
    return NULL;
}

static void pingipv4SetCarrierChecksums(sbuf_t *buf)
{
    /* Both callers have already built or validated a complete, unfragmented ICMP carrier. */
    const bool checksummed = calcFullPacketChecksum(sbufGetMutablePtr(buf), sbufGetLength(buf));
    assert(checksummed);
    discard checksummed;
}

const char *pingipv4Encode(sbuf_t *buf, const ping_ipv4_config_t *config, atomic_u32_t *next_sequence)
{
    assert(buf != NULL && ! sbufIsSplice(buf));
    assert(config != NULL && (config->role == kPingIpv4Client || config->role == kPingIpv4Server));

    const size_t native_length = sbufGetLength(buf);
    if (native_length > kPingIpv4MaxInnerLength)
    {
        return "native IPv4 packet exceeds the Ping carrier limit";
    }
    uint8_t           *packet = sbufGetMutablePtr(buf);
    ipv4_packet_view_t native = {0};
    const char        *error  = pingipv4PacketError(packet, (uint32_t) native_length, &native);
    if (error != NULL)
    {
        return error;
    }
    if (native.fragmented)
    {
        return "fragmented native IPv4 packet requires adapter reassembly before Ping";
    }
    if (! pingwireNativeShape(packet + native.transport_offset, native.transport_length, native.protocol))
    {
        return "invalid native TCP, UDP, or ICMP geometry";
    }
    if (sbufGetHeadroom(buf) < kPingIpv4Overhead)
    {
        return "insufficient left headroom for the Ping ICMP prefix and trailer";
    }
    if (sbufGetRecalculateChecksum(buf) && ! calcFullPacketChecksum(packet, native_length))
    {
        return "requested native IPv4/transport checksum repair failed";
    }

    if (native.protocol == IPPROTO_TCP || native.protocol == IPPROTO_UDP)
    {
        const bool normalized = updateIpv4TransportChecksumAddresses(
            packet, native_length, native.protocol, native.source_address, native.destination_address, 0, 0);
        assert(normalized);
        discard normalized;
    }

    const uint16_t carrier_length = (uint16_t) (native_length + kPingIpv4Overhead);
    packet                        = sbufShiftLeft(buf, kPingIpv4Overhead);
    /* Move the header first, then slide the body left to make room for the trailer. */
    memmove(packet, packet + kPingIpv4Overhead, native.ip_header_length);
    uint8_t *icmp = packet + native.ip_header_length;
    memmove(icmp + kPingIpv4IcmpPrefixLength, icmp + kPingIpv4Overhead, native.transport_length);

    memoryZero(icmp, kPingIpv4IcmpPrefixLength);
    icmp[0] = config->type;
    icmp[1] = config->code;
    if (next_sequence != NULL)
    {
        const uint16_t sequence = (uint16_t) atomicAddU32Explicit(next_sequence, 1U, memory_order_relaxed);
        icmp[4]                 = (uint8_t) (config->identifier >> 8);
        icmp[5]                 = (uint8_t) config->identifier;
        icmp[6]                 = (uint8_t) (sequence >> 8);
        icmp[7]                 = (uint8_t) sequence;
    }
    packet[carrier_length - kPingIpv4TrailerLength] = native.protocol;
    packet[carrier_length - 1U]                     = (uint8_t) config->role;

    struct ip_hdr *ip = (struct ip_hdr *) packet;
    IPH_PROTO_SET(ip, IP_PROTO_ICMP);
    IPH_LEN_SET(ip, lwip_htons(carrier_length));

    pingipv4SetCarrierChecksums(buf);
    sbufSetRecalculateChecksum(buf, false);
    return NULL;
}

const char *pingipv4Decode(sbuf_t *buf, const ping_ipv4_config_t *config, buffer_pool_t *reply_pool, sbuf_t **reply_out)
{
    assert(buf != NULL && ! sbufIsSplice(buf));
    assert(config != NULL && (config->role == kPingIpv4Client || config->role == kPingIpv4Server));
    assert(reply_pool == NULL || (reply_out != NULL && *reply_out == NULL));

    const size_t carrier_length = sbufGetLength(buf);
    if (carrier_length > kMaxAllowedPacketLength)
    {
        return "IPv4 packet exceeds the Ping carrier limit";
    }
    uint8_t           *packet  = sbufGetMutablePtr(buf);
    ipv4_packet_view_t carrier = {0};
    const char        *error   = pingipv4PacketError(packet, (uint32_t) carrier_length, &carrier);
    if (error != NULL)
    {
        return error;
    }
    if (carrier.fragmented)
    {
        return "fragmented carrier IPv4 packet requires adapter reassembly before Ping";
    }
    if (carrier.protocol != IP_PROTO_ICMP)
    {
        return "carrier IPv4 protocol is not ICMP";
    }
    if (carrier.transport_length < kPingIpv4Overhead)
    {
        return "truncated Ping ICMP prefix or trailer";
    }

    uint8_t               *icmp        = packet + carrier.transport_offset;
    const uint16_t         icmp_length = carrier.transport_length;
    const uint8_t          protocol    = icmp[icmp_length - kPingIpv4TrailerLength];
    const ping_ipv4_role_t peer_role   = config->role == kPingIpv4Client ? kPingIpv4Server : kPingIpv4Client;
    if (icmp[icmp_length - 1U] != (uint8_t) peer_role)
    {
        return "Ping frame sender role does not match the peer";
    }

    const uint16_t body_length = (uint16_t) (icmp_length - kPingIpv4Overhead);
    if (! pingwireNativeShape(icmp + kPingIpv4IcmpPrefixLength, body_length, protocol))
    {
        return "invalid native TCP, UDP, or ICMP geometry";
    }

    if (sbufGetRecalculateChecksum(buf))
    {
        pingipv4SetCarrierChecksums(buf);
    }
    else
    {
        if (calcGenericChecksum(packet, carrier.ip_header_length, 0) != 0)
        {
            return "invalid carrier IPv4 checksum";
        }
        if (calcGenericChecksum(icmp, icmp_length, 0) != 0)
        {
            return "invalid carrier ICMP checksum";
        }
    }

    if (reply_pool != NULL && icmp[0] == ICMP_ECHO && icmp[1] == 0)
    {
        sbuf_t        *reply        = sbufDuplicateByPool(reply_pool, buf);
        uint8_t       *reply_packet = sbufGetMutablePtr(reply);
        struct ip_hdr *reply_ip     = (struct ip_hdr *) reply_packet;
        reply_ip->src.addr          = carrier.destination_address;
        reply_ip->dest.addr         = carrier.source_address;
        IPH_ID_SET(reply_ip, lwip_htons((uint16_t) fastRand32()));
        IPH_TTL_SET(reply_ip, 64);
        IPH_OFFSET_SET(reply_ip, 0);
        /* Keep the request's role trailer so the sender still rejects the reflected payload. */
        reply_packet[carrier.transport_offset] = ICMP_ER;
        pingipv4SetCarrierChecksums(reply);
        sbufSetRecalculateChecksum(reply, false);
        *reply_out = reply;
    }

    const uint16_t native_length = (uint16_t) (carrier_length - kPingIpv4Overhead);
    /* Move the body into the trailer's space before moving the header. */
    memmove(icmp + kPingIpv4Overhead, icmp + kPingIpv4IcmpPrefixLength, body_length);
    memmove(packet + kPingIpv4Overhead, packet, carrier.ip_header_length);
    packet            = sbufShiftRight(buf, kPingIpv4Overhead);
    struct ip_hdr *ip = (struct ip_hdr *) packet;
    IPH_PROTO_SET(ip, protocol);
    IPH_LEN_SET(ip, lwip_htons(native_length));

    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
    {
        const bool restored = updateIpv4TransportChecksumAddresses(
            packet, native_length, protocol, 0, 0, carrier.source_address, carrier.destination_address);
        assert(restored);
        discard restored;
    }
    const bool repaired = calcIpv4HeaderChecksum(packet, native_length);
    assert(repaired);
    discard repaired;

    sbufSetRecalculateChecksum(buf, false);
    return NULL;
}
