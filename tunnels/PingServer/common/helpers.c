#include "structure.h"

#include "loggers/network_logger.h"

enum
{
    kIpv4MinHeaderLength          = 20,
    kIpv4FragmentMask            = 0x3FFF,
    kPingServerReuseTrailerMagic0 = 0x57,
    kPingServerReuseTrailerMagic1 = 0x50
};

static uint8_t pingserverPeekPacketVersion(sbuf_t *buf)
{
    if (sbufGetLength(buf) == 0)
    {
        return 0;
    }

    const uint8_t *packet = (const uint8_t *) sbufGetRawPtr(buf);
    return (uint8_t) (packet[0] >> 4);
}

static void pingserverLogIpv6Passthrough(const char *path)
{
    LOGW("PingServer: forwarding IPv6 packet unchanged on %s path because this strategy only rewrites IPv4", path);
}

static bool pingserverValidateIpv4PacketBytes(const uint8_t *packet, uint32_t available_len, uint16_t *packet_len_out)
{
    if (UNLIKELY(available_len < sizeof(struct ip_hdr)))
    {
        return false;
    }

    const struct ip_hdr *ipheader         = (const struct ip_hdr *) packet;
    const uint16_t       ip_header_len    = IPH_HL_BYTES(ipheader);
    const uint16_t       total_packet_len = lwip_ntohs(IPH_LEN(ipheader));

    if (UNLIKELY(IPH_V(ipheader) != 4))
    {
        return false;
    }

    if (UNLIKELY(ip_header_len < kIpv4MinHeaderLength || total_packet_len < ip_header_len ||
                 total_packet_len != available_len))
    {
        return false;
    }

    *packet_len_out = total_packet_len;
    return true;
}

static bool pingserverIpv4PacketIsFragmented(const struct ip_hdr *ipheader)
{
    return (lwip_ntohs(IPH_OFFSET(ipheader)) & kIpv4FragmentMask) != 0;
}

static void pingserverRecalculateIpv4HeaderChecksum(struct ip_hdr *ipheader)
{
    IPH_CHKSUM_SET(ipheader, 0);
    IPH_CHKSUM_SET(ipheader, inet_chksum(ipheader, IPH_HL_BYTES(ipheader)));
}

static void pingserverXorPayload(uint8_t *payload, uint16_t payload_len, uint8_t xor_byte)
{
    for (uint16_t i = 0; i < payload_len; ++i)
    {
        payload[i] ^= xor_byte;
    }
}

static bool pingserverCheckPacketLengthLimit(const char *operation, uint32_t packet_len)
{
    if (UNLIKELY(packet_len > kMaxAllowedPacketLength))
    {
        LOGW("PingServer: dropping packet because %s would exceed kMaxAllowedPacketLength: %u > %u", operation,
             (unsigned int) packet_len, (unsigned int) kMaxAllowedPacketLength);
        return false;
    }

    return true;
}

static bool pingserverChooseRoundupPayloadLength(uint16_t payload_with_size_len, uint16_t max_payload_len,
                                                 uint16_t *roundup_payload_len_out)
{
    static const uint16_t kRoundupBuckets[] = {64, 128, 256, 512, 1024};

    for (size_t i = 0; i < ARRAY_SIZE(kRoundupBuckets); ++i)
    {
        if (payload_with_size_len <= kRoundupBuckets[i] && kRoundupBuckets[i] <= max_payload_len)
        {
            *roundup_payload_len_out = kRoundupBuckets[i];
            return true;
        }
    }

    if (payload_with_size_len <= max_payload_len)
    {
        *roundup_payload_len_out = max_payload_len;
        return true;
    }

    return false;
}

static void pingserverFillIcmpEchoHeader(pingserver_tstate_t *state, struct icmp_echo_hdr *icmpheader)
{
    ICMPH_TYPE_SET(icmpheader, ICMP_ECHO);
    ICMPH_CODE_SET(icmpheader, 0);
    icmpheader->chksum = 0;
    icmpheader->id     = lwip_htons(state->identifier);
    icmpheader->seqno  = lwip_htons((uint16_t) (atomicAdd(&(state->icmp_sequence), 1U) + 1U));
}

static void pingserverWriteReuseTrailer(uint8_t *trailer, uint8_t original_protocol, uint16_t transport_len)
{
    trailer[0] = kPingServerReuseTrailerMagic0;
    trailer[1] = kPingServerReuseTrailerMagic1;
    trailer[2] = original_protocol;
    trailer[3] = (uint8_t) ((transport_len >> 8) & 0xFFU);
    trailer[4] = (uint8_t) (transport_len & 0xFFU);
}

static bool pingserverReadReuseTrailer(const uint8_t *icmp_payload, uint16_t icmp_payload_len,
                                       uint8_t *original_protocol_out, uint16_t *transport_len_out)
{
    if (UNLIKELY(icmp_payload_len < kPingServerReuseTrailerLength))
    {
        return false;
    }

    const uint8_t *trailer = icmp_payload + icmp_payload_len - kPingServerReuseTrailerLength;
    if (UNLIKELY(trailer[0] != kPingServerReuseTrailerMagic0 || trailer[1] != kPingServerReuseTrailerMagic1))
    {
        return false;
    }

    *original_protocol_out = trailer[2];
    *transport_len_out     = (uint16_t) ((((uint16_t) trailer[3]) << 8) | trailer[4]);
    return true;
}

static sbuf_t *pingserverPrepareNewIpPayloadBuffer(tunnel_t *t, line_t *l, sbuf_t *buf,
                                                   uint16_t *icmp_payload_len_out,
                                                   uint32_t *inner_source_addr_out, uint32_t *inner_dest_addr_out)
{
    pingserver_tstate_t *state = tunnelGetState(t);
    uint16_t             inner_packet_len;

    if (! pingserverValidateIpv4PacketBytes(sbufGetRawPtr(buf), sbufGetLength(buf), &inner_packet_len))
    {
        return NULL;
    }

    const struct ip_hdr *inner_ipheader = (const struct ip_hdr *) sbufGetRawPtr(buf);
    *inner_source_addr_out              = inner_ipheader->src.addr;
    *inner_dest_addr_out                = inner_ipheader->dest.addr;

    if (lineGetRecalculateChecksum(l))
    {
        calcFullPacketChecksum(sbufGetMutablePtr(buf));
        lineSetRecalculateChecksum(l, false);
    }

    uint16_t icmp_payload_len = inner_packet_len;

    if (state->roundup_payload_size)
    {
        if (UNLIKELY(inner_packet_len > kPingServerMaxIcmpPayloadLength - kPingServerSizePrefixLength))
        {
            LOGW("PingServer: dropping packet because roundup-size needs %u bytes but ICMP payload is capped at %u",
                 (unsigned int) (inner_packet_len + kPingServerSizePrefixLength),
                 (unsigned int) kPingServerMaxIcmpPayloadLength);
            return NULL;
        }

        const uint16_t payload_with_size_len = (uint16_t) (inner_packet_len + kPingServerSizePrefixLength);
        if (! pingserverChooseRoundupPayloadLength(payload_with_size_len, kPingServerMaxIcmpPayloadLength,
                                                   &icmp_payload_len))
        {
            LOGW("PingServer: dropping packet because roundup-size cannot fit %u bytes inside the ICMP payload limit",
                 (unsigned int) payload_with_size_len);
            return NULL;
        }

        buf = sbufReserveSpace(buf, icmp_payload_len);

        uint8_t *payload = sbufGetMutablePtr(buf);
        memoryMove(payload + kPingServerSizePrefixLength, payload, inner_packet_len);
        payload[0] = (uint8_t) ((inner_packet_len >> 8) & 0xFFU);
        payload[1] = (uint8_t) (inner_packet_len & 0xFFU);

        if (icmp_payload_len > payload_with_size_len)
        {
            getRandomBytes(payload + payload_with_size_len, (size_t) (icmp_payload_len - payload_with_size_len));
        }

        sbufSetLength(buf, icmp_payload_len);
    }
    else if (UNLIKELY(inner_packet_len > kPingServerMaxIcmpPayloadLength))
    {
        LOGW("PingServer: inner IPv4 packet exceeds ICMP payload size limit: %u > %u", inner_packet_len,
             (unsigned int) kPingServerMaxIcmpPayloadLength);
        return NULL;
    }

    if (state->payload_xor_enabled)
    {
        pingserverXorPayload(sbufGetMutablePtr(buf), icmp_payload_len, state->payload_xor_byte);
    }

    *icmp_payload_len_out = icmp_payload_len;
    return buf;
}

static sbuf_t *pingserverPrepareRawIcmpPayloadBuffer(tunnel_t *t, line_t *l, sbuf_t *buf,
                                                     uint16_t *icmp_payload_len_out)
{
    pingserver_tstate_t *state   = tunnelGetState(t);
    uint32_t             raw_len = sbufGetLength(buf);

    if (lineGetRecalculateChecksum(l))
    {
        uint16_t packet_len;
        if (pingserverValidateIpv4PacketBytes(sbufGetRawPtr(buf), raw_len, &packet_len))
        {
            calcFullPacketChecksum(sbufGetMutablePtr(buf));
        }
        lineSetRecalculateChecksum(l, false);
    }

    if (UNLIKELY(raw_len > UINT16_MAX))
    {
        LOGW("PingServer: dropping raw payload because it is too large for an ICMP frame: %u",
             (unsigned int) raw_len);
        return NULL;
    }

    uint16_t icmp_payload_len = (uint16_t) raw_len;

    if (state->roundup_payload_size)
    {
        if (UNLIKELY(raw_len > kPingServerMaxOnlyIcmpPayloadLength - kPingServerSizePrefixLength))
        {
            LOGW("PingServer: dropping raw payload because roundup-size needs %u bytes but ICMP payload is capped at %u",
                 (unsigned int) (raw_len + kPingServerSizePrefixLength),
                 (unsigned int) kPingServerMaxOnlyIcmpPayloadLength);
            return NULL;
        }

        const uint16_t payload_with_size_len = (uint16_t) (raw_len + kPingServerSizePrefixLength);
        if (! pingserverChooseRoundupPayloadLength(payload_with_size_len, kPingServerMaxOnlyIcmpPayloadLength,
                                                   &icmp_payload_len))
        {
            LOGW("PingServer: dropping raw payload because roundup-size cannot fit %u bytes inside the ICMP payload limit",
                 (unsigned int) payload_with_size_len);
            return NULL;
        }

        buf = sbufReserveSpace(buf, icmp_payload_len);

        uint8_t *payload = sbufGetMutablePtr(buf);
        memoryMove(payload + kPingServerSizePrefixLength, payload, raw_len);
        payload[0] = (uint8_t) ((raw_len >> 8) & 0xFFU);
        payload[1] = (uint8_t) (raw_len & 0xFFU);

        if (icmp_payload_len > payload_with_size_len)
        {
            getRandomBytes(payload + payload_with_size_len, (size_t) (icmp_payload_len - payload_with_size_len));
        }

        sbufSetLength(buf, icmp_payload_len);
    }
    else if (UNLIKELY(raw_len > kPingServerMaxOnlyIcmpPayloadLength))
    {
        LOGW("PingServer: raw payload exceeds ICMP payload size limit: %u > %u", (unsigned int) raw_len,
             (unsigned int) kPingServerMaxOnlyIcmpPayloadLength);
        return NULL;
    }

    if (state->payload_xor_enabled)
    {
        pingserverXorPayload(sbufGetMutablePtr(buf), icmp_payload_len, state->payload_xor_byte);
    }

    *icmp_payload_len_out = icmp_payload_len;
    return buf;
}

static bool pingserverIcmpTypeIsAccepted(uint8_t type)
{
    return type == ICMP_ECHO || type == ICMP_ER;
}

static bool pingserverMatchIpv4IcmpEnvelope(const pingserver_tstate_t *state, sbuf_t *buf,
                                            uint16_t *outer_header_len_out)
{
    if (UNLIKELY(sbufGetLength(buf) < kPingServerEncapsulationOverhead))
    {
        return false;
    }

    const uint8_t       *packet   = sbufGetRawPtr(buf);
    const struct ip_hdr *ipheader = (const struct ip_hdr *) packet;

    if (UNLIKELY(IPH_V(ipheader) != 4))
    {
        return false;
    }

    const uint16_t ip_header_len = IPH_HL_BYTES(ipheader);
    if (UNLIKELY(ip_header_len < kIpv4MinHeaderLength))
    {
        return false;
    }

    if (UNLIKELY(sbufGetLength(buf) < (uint32_t) ip_header_len + kPingServerIcmpHeaderLength))
    {
        return false;
    }

    const uint16_t total_packet_len = lwip_ntohs(IPH_LEN(ipheader));
    if (UNLIKELY(total_packet_len != sbufGetLength(buf)))
    {
        return false;
    }

    if (UNLIKELY(total_packet_len > kMaxAllowedPacketLength))
    {
        return false;
    }

    if (IPH_PROTO(ipheader) != IP_PROTO_ICMP)
    {
        return false;
    }

    if (UNLIKELY(pingserverIpv4PacketIsFragmented(ipheader)))
    {
        return false;
    }

    const struct icmp_echo_hdr *icmpheader = (const struct icmp_echo_hdr *) (packet + ip_header_len);
    if (! pingserverIcmpTypeIsAccepted(icmpheader->type) || icmpheader->code != 0 ||
        icmpheader->id != lwip_htons(state->identifier))
    {
        return false;
    }

    *outer_header_len_out = (uint16_t) (ip_header_len + kPingServerIcmpHeaderLength);
    return true;
}

static bool pingserverMatchOnlyIcmpEnvelope(const pingserver_tstate_t *state, sbuf_t *buf)
{
    if (UNLIKELY(sbufGetLength(buf) < kPingServerIcmpHeaderLength ||
                 sbufGetLength(buf) > kMaxAllowedPacketLength))
    {
        return false;
    }

    const struct icmp_echo_hdr *icmpheader = (const struct icmp_echo_hdr *) sbufGetRawPtr(buf);
    return pingserverIcmpTypeIsAccepted(icmpheader->type) && icmpheader->code == 0 &&
           icmpheader->id == lwip_htons(state->identifier);
}

static bool pingserverHandleUnmatchedUpstreamPacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    tunnelNextUpStreamPayload(t, l, buf);
    return true;
}

static void pingserverEncapsulateWithNewIpAndIcmp(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingserver_tstate_t *state = tunnelGetState(t);
    uint16_t             icmp_payload_len;
    uint32_t             inner_source_addr;
    uint32_t             inner_dest_addr;

    sbuf_t *prepared_buf =
        pingserverPrepareNewIpPayloadBuffer(t, l, buf, &icmp_payload_len, &inner_source_addr, &inner_dest_addr);
    if (prepared_buf == NULL)
    {
        if (pingserverPeekPacketVersion(buf) == 6)
        {
            pingserverLogIpv6Passthrough("downstream");
        }
        else
        {
            LOGW("PingServer: forwarding downstream packet unchanged because IPv4+ICMP encapsulation requires a valid IPv4 packet");
        }

        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }
    buf = prepared_buf;

    const uint32_t packet_len = (uint32_t) icmp_payload_len + kPingServerEncapsulationOverhead;
    if (! pingserverCheckPacketLengthLimit("IPv4+ICMP encapsulation", packet_len))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (UNLIKELY(sbufGetLeftCapacity(buf) < kPingServerEncapsulationOverhead))
    {
        LOGW("PingServer: dropping packet without enough left padding for IPv4+ICMP encapsulation");
        lineReuseBuffer(l, buf);
        return;
    }

    sbufShiftLeft(buf, kPingServerEncapsulationOverhead);

    uint8_t              *packet     = sbufGetMutablePtr(buf);
    struct ip_hdr        *ipheader   = (struct ip_hdr *) packet;
    struct icmp_echo_hdr *icmpheader = (struct icmp_echo_hdr *) (packet + kPingServerIpv4HeaderLength);

    memorySet(packet, 0, kPingServerEncapsulationOverhead);

    IPH_VHL_SET(ipheader, 4, sizeof(struct ip_hdr) / 4U);
    IPH_TOS_SET(ipheader, state->tos);
    IPH_LEN_SET(ipheader, lwip_htons((uint16_t) packet_len));
    IPH_ID_SET(ipheader, lwip_htons((uint16_t) (atomicAdd(&(state->ipv4_identification), 1U) + 1U)));
    IPH_OFFSET_SET(ipheader, 0);
    IPH_TTL_SET(ipheader, state->ttl);
    IPH_PROTO_SET(ipheader, IP_PROTO_ICMP);
    IPH_CHKSUM_SET(ipheader, 0);
    ipheader->src.addr  = state->source_addr_configured ? state->source_addr : inner_source_addr;
    ipheader->dest.addr = state->dest_addr_configured ? state->dest_addr : inner_dest_addr;

    pingserverFillIcmpEchoHeader(state, icmpheader);

    calcFullPacketChecksum(packet);
    lineSetRecalculateChecksum(l, false);

    tunnelPrevDownStreamPayload(t, l, buf);
}

static void pingserverEncapsulateReusingIpv4Header(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingserver_tstate_t *state = tunnelGetState(t);
    uint16_t             packet_len;

    if (! pingserverValidateIpv4PacketBytes(sbufGetRawPtr(buf), sbufGetLength(buf), &packet_len))
    {
        if (pingserverPeekPacketVersion(buf) == 6)
        {
            pingserverLogIpv6Passthrough("downstream");
        }
        else
        {
            LOGW("PingServer: forwarding downstream packet unchanged because reuse-header mode requires a valid IPv4 packet");
        }
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }

    if (lineGetRecalculateChecksum(l))
    {
        calcFullPacketChecksum(sbufGetMutablePtr(buf));
        lineSetRecalculateChecksum(l, false);
    }

    const struct ip_hdr *initial_ipheader = (const struct ip_hdr *) sbufGetRawPtr(buf);
    const uint16_t       ip_header_len    = IPH_HL_BYTES(initial_ipheader);
    const uint16_t       transport_len    = (uint16_t) (packet_len - ip_header_len);
    const uint8_t        original_protocol = IPH_PROTO(initial_ipheader);

    if (UNLIKELY(pingserverIpv4PacketIsFragmented(initial_ipheader)))
    {
        LOGW("PingServer: forwarding fragmented IPv4 packet unchanged because reuse-header mode cannot restore fragments safely");
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }

    if (UNLIKELY(kMaxAllowedPacketLength < (uint32_t) ip_header_len + kPingServerIcmpHeaderLength +
                                               kPingServerReuseTrailerLength))
    {
        LOGW("PingServer: forwarding packet unchanged because the IPv4 header leaves no room for ICMP reuse metadata");
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }

    const uint16_t max_icmp_payload_len =
        (uint16_t) (kMaxAllowedPacketLength - ip_header_len - kPingServerIcmpHeaderLength);
    uint16_t icmp_payload_len = (uint16_t) (transport_len + kPingServerReuseTrailerLength);

    if (state->roundup_payload_size)
    {
        if (! pingserverChooseRoundupPayloadLength(icmp_payload_len, max_icmp_payload_len, &icmp_payload_len))
        {
            LOGW("PingServer: forwarding packet unchanged because reuse-header roundup payload cannot fit inside the ICMP payload limit");
            tunnelPrevDownStreamPayload(t, l, buf);
            return;
        }
    }
    else if (UNLIKELY(icmp_payload_len > max_icmp_payload_len))
    {
        LOGW("PingServer: forwarding packet unchanged because reuse-header ICMP payload exceeds size limit: %u > %u",
             (unsigned int) icmp_payload_len, (unsigned int) max_icmp_payload_len);
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }

    const uint32_t final_packet_len = (uint32_t) ip_header_len + kPingServerIcmpHeaderLength + icmp_payload_len;
    if (! pingserverCheckPacketLengthLimit("reuse-header ICMP encapsulation", final_packet_len))
    {
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }

    buf = sbufReserveSpace(buf, final_packet_len);

    uint8_t              *packet       = sbufGetMutablePtr(buf);
    struct ip_hdr        *ipheader     = (struct ip_hdr *) packet;
    struct icmp_echo_hdr *icmpheader   = (struct icmp_echo_hdr *) (packet + ip_header_len);
    uint8_t              *icmp_payload = packet + ip_header_len + kPingServerIcmpHeaderLength;
    uint8_t              *transport    = packet + ip_header_len;

    memoryMove(icmp_payload, transport, transport_len);

    const uint16_t padding_len = (uint16_t) (icmp_payload_len - transport_len - kPingServerReuseTrailerLength);
    if (padding_len > 0)
    {
        getRandomBytes(icmp_payload + transport_len, padding_len);
    }

    pingserverWriteReuseTrailer(icmp_payload + icmp_payload_len - kPingServerReuseTrailerLength, original_protocol,
                                transport_len);

    if (state->payload_xor_enabled)
    {
        pingserverXorPayload(icmp_payload, icmp_payload_len, state->payload_xor_byte);
    }

    memorySet(icmpheader, 0, kPingServerIcmpHeaderLength);
    pingserverFillIcmpEchoHeader(state, icmpheader);

    IPH_LEN_SET(ipheader, lwip_htons((uint16_t) final_packet_len));
    IPH_PROTO_SET(ipheader, IP_PROTO_ICMP);
    IPH_CHKSUM_SET(ipheader, 0);
    sbufSetLength(buf, final_packet_len);

    calcFullPacketChecksum(packet);
    lineSetRecalculateChecksum(l, false);

    tunnelPrevDownStreamPayload(t, l, buf);
}

static void pingserverEncapsulateOnlyIcmp(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingserver_tstate_t *state = tunnelGetState(t);
    uint16_t             icmp_payload_len;

    sbuf_t *prepared_buf = pingserverPrepareRawIcmpPayloadBuffer(t, l, buf, &icmp_payload_len);
    if (prepared_buf == NULL)
    {
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }
    buf = prepared_buf;

    const uint32_t frame_len = (uint32_t) icmp_payload_len + kPingServerIcmpHeaderLength;
    if (! pingserverCheckPacketLengthLimit("ICMP-only encapsulation", frame_len))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (UNLIKELY(sbufGetLeftCapacity(buf) < kPingServerIcmpHeaderLength))
    {
        LOGW("PingServer: dropping raw payload without enough left padding for ICMP-only encapsulation");
        lineReuseBuffer(l, buf);
        return;
    }

    sbufShiftLeft(buf, kPingServerIcmpHeaderLength);

    uint8_t              *frame      = sbufGetMutablePtr(buf);
    struct icmp_echo_hdr *icmpheader = (struct icmp_echo_hdr *) frame;

    memorySet(icmpheader, 0, kPingServerIcmpHeaderLength);
    pingserverFillIcmpEchoHeader(state, icmpheader);
    icmpheader->chksum = calcGenericChecksum(frame, (uint16_t) frame_len, 0);
    lineSetRecalculateChecksum(l, false);

    tunnelPrevDownStreamPayload(t, l, buf);
}

static void pingserverForwardDecodedUpstream(tunnel_t *t, line_t *l, sbuf_t *buf, uint16_t header_len,
                                             uint16_t payload_len_after_strip, bool has_size_prefix)
{
    sbufShiftRight(buf, header_len);

    if (has_size_prefix)
    {
        memoryMove(sbufGetMutablePtr(buf), sbufGetMutablePtr(buf) + kPingServerSizePrefixLength,
                   payload_len_after_strip);
    }

    sbufSetLength(buf, payload_len_after_strip);
    lineSetRecalculateChecksum(l, false);

    tunnelNextUpStreamPayload(t, l, buf);
}

static void pingserverDecapsulateNewIpAndIcmp(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingserver_tstate_t *state = tunnelGetState(t);
    uint16_t             outer_header_len;

    if (! pingserverMatchIpv4IcmpEnvelope(state, buf, &outer_header_len))
    {
        pingserverHandleUnmatchedUpstreamPacket(t, l, buf);
        return;
    }

    uint8_t *icmp_payload             = sbufGetMutablePtr(buf) + outer_header_len;
    uint16_t icmp_payload_len         = (uint16_t) (sbufGetLength(buf) - outer_header_len);
    bool     payload_decoded_in_place = false;

    if (state->payload_xor_enabled)
    {
        pingserverXorPayload(icmp_payload, icmp_payload_len, state->payload_xor_byte);
        payload_decoded_in_place = true;
    }

    uint16_t inner_packet_len = icmp_payload_len;
    bool     has_size_prefix  = false;

    if (state->roundup_payload_size)
    {
        if (UNLIKELY(icmp_payload_len < kPingServerSizePrefixLength))
        {
            if (payload_decoded_in_place)
            {
                pingserverXorPayload(icmp_payload, icmp_payload_len, state->payload_xor_byte);
            }
            tunnelNextUpStreamPayload(t, l, buf);
            return;
        }

        inner_packet_len = (uint16_t) ((((uint16_t) icmp_payload[0]) << 8) | icmp_payload[1]);
        if (UNLIKELY(inner_packet_len > icmp_payload_len - kPingServerSizePrefixLength))
        {
            if (payload_decoded_in_place)
            {
                pingserverXorPayload(icmp_payload, icmp_payload_len, state->payload_xor_byte);
            }
            tunnelNextUpStreamPayload(t, l, buf);
            return;
        }

        has_size_prefix = true;
    }

    pingserverForwardDecodedUpstream(t, l, buf, outer_header_len, inner_packet_len, has_size_prefix);
}

static void pingserverDecapsulateReusedIpv4Header(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingserver_tstate_t *state = tunnelGetState(t);
    uint16_t             outer_header_len;

    if (! pingserverMatchIpv4IcmpEnvelope(state, buf, &outer_header_len))
    {
        pingserverHandleUnmatchedUpstreamPacket(t, l, buf);
        return;
    }

    uint8_t *packet                   = sbufGetMutablePtr(buf);
    struct ip_hdr *ipheader           = (struct ip_hdr *) packet;
    const uint16_t ip_header_len      = IPH_HL_BYTES(ipheader);
    uint8_t       *icmp_payload       = packet + outer_header_len;
    uint16_t       icmp_payload_len   = (uint16_t) (sbufGetLength(buf) - outer_header_len);
    bool           decoded_in_place   = false;

    if (state->payload_xor_enabled)
    {
        pingserverXorPayload(icmp_payload, icmp_payload_len, state->payload_xor_byte);
        decoded_in_place = true;
    }

    uint8_t  original_protocol;
    uint16_t transport_len;
    if (! pingserverReadReuseTrailer(icmp_payload, icmp_payload_len, &original_protocol, &transport_len))
    {
        if (decoded_in_place)
        {
            pingserverXorPayload(icmp_payload, icmp_payload_len, state->payload_xor_byte);
        }
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    if (UNLIKELY(transport_len > icmp_payload_len - kPingServerReuseTrailerLength))
    {
        if (decoded_in_place)
        {
            pingserverXorPayload(icmp_payload, icmp_payload_len, state->payload_xor_byte);
        }
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    const uint16_t restored_packet_len = (uint16_t) (ip_header_len + transport_len);
    memoryMove(packet + ip_header_len, icmp_payload, transport_len);
    sbufSetLength(buf, restored_packet_len);

    IPH_LEN_SET(ipheader, lwip_htons(restored_packet_len));
    IPH_PROTO_SET(ipheader, original_protocol);
    calcFullPacketChecksum(packet);
    lineSetRecalculateChecksum(l, false);

    tunnelNextUpStreamPayload(t, l, buf);
}

static void pingserverDecapsulateOnlyIcmp(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingserver_tstate_t *state = tunnelGetState(t);

    if (! pingserverMatchOnlyIcmpEnvelope(state, buf))
    {
        tunnelNextUpStreamPayload(t, l, buf);
        return;
    }

    uint8_t *icmp_payload             = sbufGetMutablePtr(buf) + kPingServerIcmpHeaderLength;
    uint16_t icmp_payload_len         = (uint16_t) (sbufGetLength(buf) - kPingServerIcmpHeaderLength);
    bool     payload_decoded_in_place = false;

    if (state->payload_xor_enabled)
    {
        pingserverXorPayload(icmp_payload, icmp_payload_len, state->payload_xor_byte);
        payload_decoded_in_place = true;
    }

    uint16_t raw_payload_len = icmp_payload_len;
    bool     has_size_prefix = false;

    if (state->roundup_payload_size)
    {
        if (UNLIKELY(icmp_payload_len < kPingServerSizePrefixLength))
        {
            if (payload_decoded_in_place)
            {
                pingserverXorPayload(icmp_payload, icmp_payload_len, state->payload_xor_byte);
            }
            tunnelNextUpStreamPayload(t, l, buf);
            return;
        }

        raw_payload_len = (uint16_t) ((((uint16_t) icmp_payload[0]) << 8) | icmp_payload[1]);
        if (UNLIKELY(raw_payload_len > icmp_payload_len - kPingServerSizePrefixLength))
        {
            if (payload_decoded_in_place)
            {
                pingserverXorPayload(icmp_payload, icmp_payload_len, state->payload_xor_byte);
            }
            tunnelNextUpStreamPayload(t, l, buf);
            return;
        }

        has_size_prefix = true;
    }

    pingserverForwardDecodedUpstream(t, l, buf, kPingServerIcmpHeaderLength, raw_payload_len, has_size_prefix);
}

static void pingserverSwapIpv4ProtocolToIcmp(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingserver_tstate_t *state = tunnelGetState(t);
    uint16_t             packet_len;

    if (! pingserverValidateIpv4PacketBytes(sbufGetRawPtr(buf), sbufGetLength(buf), &packet_len))
    {
        discard packet_len;
        if (pingserverPeekPacketVersion(buf) == 6)
        {
            pingserverLogIpv6Passthrough("downstream");
        }
        else
        {
            LOGW("PingServer: forwarding downstream packet unchanged because protocol-swap mode requires a valid IPv4 packet");
        }
        tunnelPrevDownStreamPayload(t, l, buf);
        return;
    }

    if (lineGetRecalculateChecksum(l))
    {
        calcFullPacketChecksum(sbufGetMutablePtr(buf));
        lineSetRecalculateChecksum(l, false);
    }

    struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);
    if (IPH_PROTO(ipheader) == state->swap_protocol)
    {
        IPH_PROTO_SET(ipheader, IP_PROTO_ICMP);
        pingserverRecalculateIpv4HeaderChecksum(ipheader);
        lineSetRecalculateChecksum(l, false);
    }

    tunnelPrevDownStreamPayload(t, l, buf);
}

static void pingserverRestoreIpv4ProtocolFromIcmp(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingserver_tstate_t *state = tunnelGetState(t);
    uint16_t             packet_len;

    if (! pingserverValidateIpv4PacketBytes(sbufGetRawPtr(buf), sbufGetLength(buf), &packet_len))
    {
        discard packet_len;
        pingserverHandleUnmatchedUpstreamPacket(t, l, buf);
        return;
    }

    struct ip_hdr *ipheader = (struct ip_hdr *) sbufGetMutablePtr(buf);
    if (IPH_PROTO(ipheader) == IP_PROTO_ICMP)
    {
        IPH_PROTO_SET(ipheader, state->swap_protocol);
        pingserverRecalculateIpv4HeaderChecksum(ipheader);
        lineSetRecalculateChecksum(l, false);
    }

    tunnelNextUpStreamPayload(t, l, buf);
}

void pingserverEncapsulatePacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingserver_tstate_t *state = tunnelGetState(t);

    switch (state->strategy)
    {
    case kPingServerStrategyWrapNewIpAndIcmpHeader:
        pingserverEncapsulateWithNewIpAndIcmp(t, l, buf);
        return;
    case kPingServerStrategyWrapIcmpHeaderAndReuseIpv4Addrs:
        pingserverEncapsulateReusingIpv4Header(t, l, buf);
        return;
    case kPingServerStrategyWrapOnlyIcmpHeader:
        pingserverEncapsulateOnlyIcmp(t, l, buf);
        return;
    case kPingServerStrategyChangeOnlyIpv4ProtocolNumber:
        pingserverSwapIpv4ProtocolToIcmp(t, l, buf);
        return;
    default:
        LOGW("PingServer: dropping packet because strategy %u is invalid", (unsigned int) state->strategy);
        lineReuseBuffer(l, buf);
        return;
    }
}

void pingserverDecapsulatePacket(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    pingserver_tstate_t *state = tunnelGetState(t);

    switch (state->strategy)
    {
    case kPingServerStrategyWrapNewIpAndIcmpHeader:
        pingserverDecapsulateNewIpAndIcmp(t, l, buf);
        return;
    case kPingServerStrategyWrapIcmpHeaderAndReuseIpv4Addrs:
        pingserverDecapsulateReusedIpv4Header(t, l, buf);
        return;
    case kPingServerStrategyWrapOnlyIcmpHeader:
        pingserverDecapsulateOnlyIcmp(t, l, buf);
        return;
    case kPingServerStrategyChangeOnlyIpv4ProtocolNumber:
        pingserverRestoreIpv4ProtocolFromIcmp(t, l, buf);
        return;
    default:
        LOGW("PingServer: dropping packet because strategy %u is invalid", (unsigned int) state->strategy);
        lineReuseBuffer(l, buf);
        return;
    }
}
