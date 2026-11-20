#include "PingCommon/ping_wire.h"

/* Packet fields use network byte order; tracker integers use host order. */

const char *pingwireIpv4PacketErrorWithView(const uint8_t *packet, uint32_t length, ipv4_packet_view_t *view)
{
    if (packet == NULL || length < IP_HLEN)
    {
        return "truncated IPv4 header";
    }
    if (! ipv4packetviewParse(packet, length, view))
    {
        const struct ip_hdr *ip = (const struct ip_hdr *) packet;
        if (IPH_V(ip) != 4)
        {
            return "unsupported IP version (IPv4 required)";
        }
        const uint16_t header_length = IPH_HL_BYTES(ip);
        if (header_length < IP_HLEN || header_length > IP_HLEN_MAX)
        {
            return "invalid IPv4 header length";
        }
        if (header_length > length)
        {
            return "truncated IPv4 header options";
        }
        if (lwip_ntohs(IPH_LEN(ip)) < header_length)
        {
            return "IPv4 total length is smaller than its header";
        }
        return "IPv4 declared total length exceeds received bytes";
    }
    if (view->ip_total_length != length)
    {
        return "IPv4 declared total length does not match received bytes";
    }
    return NULL;
}

const char *pingwireIpv4PacketError(const uint8_t *packet, uint32_t length)
{
    ipv4_packet_view_t view = {0};
    return pingwireIpv4PacketErrorWithView(packet, length, &view);
}

bool pingwireIsExactIpv4Packet(const uint8_t *packet, uint32_t length)
{
    return pingwireIpv4PacketError(packet, length) == NULL;
}

bool pingwireSelectIdentifier(bool random, uint16_t configured, uint16_t random_candidate, uint16_t *identifier_out)
{
    if (identifier_out == NULL || (random && random_candidate == 0))
    {
        return false;
    }

    *identifier_out = random ? random_candidate : configured;
    return true;
}

/* Match the shared native transport geometry, including permitted UDP padding. */
bool pingwireNativeShape(const uint8_t *body, uint16_t length, uint8_t protocol)
{
    if (protocol == IPPROTO_TCP)
    {
        if (length < 20)
        {
            return false;
        }
        const uint16_t header_length = (uint16_t) ((body[12] >> 4U) * 4U);
        return header_length >= 20 && header_length <= length;
    }
    if (protocol == IPPROTO_UDP)
    {
        return length >= 8 && GET_BE16(body + 4) >= 8 && GET_BE16(body + 4) <= length;
    }
    return protocol != IPPROTO_ICMP || length >= sizeof(struct icmp_hdr);
}

const char *pingwireEchoRequestError(const sbuf_t *buf)
{
    assert(buf != NULL && ! sbufIsSplice(buf));
    ipv4_packet_view_t native = {0};
    const char        *error  = pingwireIpv4PacketErrorWithView(sbufGetRawPtr(buf), sbufGetLength(buf), &native);
    if (error != NULL)
    {
        return error;
    }
    if (native.fragmented)
    {
        return "fragmented IPv4 datagram requires adapter reassembly before Ping";
    }
    if (! pingwireNativeShape(sbufGetRawPtr(buf) + native.transport_offset, native.transport_length, native.protocol))
    {
        return "invalid native TCP, UDP, or ICMP geometry";
    }
    if (sbufGetLength(buf) > kPingWireMaxInnerPacketLength)
    {
        return "native IPv4 packet exceeds the 1491-byte limit (nine-byte Echo overhead)";
    }
    if (sbufGetHeadroom(buf) < kPingWireEncapsulationOverhead)
    {
        return "insufficient left headroom for Echo header and final protocol byte";
    }
    return NULL;
}

const char *pingwirePrepareEchoRequest(sbuf_t *buf)
{
    const char *error = pingwireEchoRequestError(buf);
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

bool pingwireEchoRequestPreflight(const sbuf_t *buf)
{
    return buf != NULL && pingwireEchoRequestError(buf) == NULL;
}

bool pingwireRecalculateEchoChecksums(sbuf_t *buf, uint8_t protocol, uint32_t checksum_seed)
{
    if (buf == NULL)
    {
        return false;
    }
    assert(! sbufIsSplice(buf));
    ipv4_packet_view_t carrier = {0};
    uint8_t           *packet  = sbufGetMutablePtr(buf);
    if (sbufGetLength(buf) > kMaxAllowedPacketLength ||
        pingwireIpv4PacketErrorWithView(packet, sbufGetLength(buf), &carrier) != NULL || carrier.fragmented ||
        carrier.protocol != protocol || carrier.transport_length < kPingWireIcmpHeaderLength)
    {
        return false;
    }
    uint8_t *echo = packet + carrier.transport_offset;
    PUT_BE16(echo + 2, 0);
    const uint16_t checksum = calcGenericChecksum(echo, carrier.transport_length, checksum_seed);
    memoryCopy(echo + 2, &checksum, sizeof(checksum));
    const bool repaired = calcIpv4HeaderChecksum(packet, sbufGetLength(buf));
    assert(repaired);
    discard repaired;
    return true;
}

bool pingwireRecalculateCarrierChecksums(sbuf_t *buf)
{
    return pingwireRecalculateEchoChecksums(buf, IP_PROTO_ICMP, 0);
}

bool pingwireBuildRequest(sbuf_t *buf, uint16_t identifier, uint16_t sequence, uint8_t protocol, uint8_t request_type,
                          uint32_t checksum_seed)
{
    if (buf == NULL || pingwirePrepareEchoRequest(buf) != NULL)
    {
        return false;
    }
    uint8_t           *packet = sbufGetMutablePtr(buf);
    ipv4_packet_view_t native = {0};
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
    const uint16_t total = (uint16_t) (native.ip_total_length + kPingWireEncapsulationOverhead);
    packet               = sbufShiftLeft(buf, kPingWireEncapsulationOverhead);
    /* Consume only left padding. The allocation's used end stays fixed, even
     * with no tailroom. Header first: its destination ends before the old body. */
    memmove(packet, packet + kPingWireEncapsulationOverhead, native.ip_header_length);
    memmove(packet + native.ip_header_length + kPingWireIcmpHeaderLength,
            packet + kPingWireEncapsulationOverhead + native.ip_header_length,
            native.transport_length);
    packet[total - 1U] = native.protocol;
    struct ip_hdr *ip  = (struct ip_hdr *) packet;
    IPH_PROTO_SET(ip, protocol);
    IPH_LEN_SET(ip, lwip_htons(total));
    uint8_t *echo = packet + native.ip_header_length;
    echo[0]       = request_type;
    echo[1]       = 0;
    PUT_BE16(echo + 4, identifier);
    PUT_BE16(echo + 6, sequence);
    const bool repaired = pingwireRecalculateEchoChecksums(buf, protocol, checksum_seed);
    assert(repaired);
    discard repaired;
    return true;
}

bool pingwireBuildEchoRequest(sbuf_t *buf, const ping_wire_config_t *config, uint16_t sequence)
{
    return config != NULL && pingwireBuildRequest(buf, config->identifier, sequence, IP_PROTO_ICMP, ICMP_ECHO, 0);
}

ping_wire_inbound_kind_t pingwireParseEcho(const uint8_t *packet, uint32_t length, uint8_t protocol,
                                           uint8_t request_type, uint8_t reply_type, uint32_t checksum_seed,
                                           ping_wire_envelope_t *envelope_out)
{
    if (envelope_out == NULL)
    {
        return kPingWireInboundMalformed;
    }
    memoryZero(envelope_out, sizeof(*envelope_out));
    ipv4_packet_view_t carrier = {0};
    envelope_out->error_reason = pingwireIpv4PacketErrorWithView(packet, length, &carrier);
    if (envelope_out->error_reason != NULL)
    {
        return kPingWireInboundMalformed;
    }
    /* Reject fragments before checksum work or native-body inspection, even
     * when the visible protocol would otherwise be unrelated. */
    if (carrier.fragmented)
    {
        envelope_out->error_reason = "fragmented IPv4 datagram requires adapter reassembly before Ping";
        return kPingWireInboundInvalidCarrier;
    }
    if (calcGenericChecksum(packet, carrier.ip_header_length, 0) != 0)
    {
        envelope_out->error_reason = "invalid carrier IPv4 checksum";
        return kPingWireInboundMalformed;
    }
    if (carrier.protocol != protocol)
    {
        return kPingWireInboundUnrelated;
    }
    if (length > kMaxAllowedPacketLength)
    {
        envelope_out->error_reason = "IPv4 packet exceeds maximum carrier size";
        return kPingWireInboundInvalidCarrier;
    }
    if (carrier.transport_length < kPingWireIcmpHeaderLength)
    {
        envelope_out->error_reason = "truncated Echo header";
        return kPingWireInboundInvalidCarrier;
    }
    const uint8_t *echo = packet + carrier.transport_offset;
    if (calcGenericChecksum(echo, carrier.transport_length, checksum_seed) != 0)
    {
        envelope_out->error_reason = "invalid Echo carrier checksum";
        return kPingWireInboundInvalidCarrier;
    }
    *envelope_out = (ping_wire_envelope_t) {
        .icmp_payload        = echo + kPingWireIcmpHeaderLength,
        .source_ipv4         = carrier.source_address,
        .destination_ipv4    = carrier.destination_address,
        .total_length        = carrier.ip_total_length,
        .icmp_payload_length = (uint16_t) (carrier.transport_length - kPingWireIcmpHeaderLength),
        .ip_header_length    = carrier.ip_header_length,
        .echo_offset         = carrier.transport_offset,
        .identifier          = GET_BE16(echo + 4),
        .sequence            = GET_BE16(echo + 6),
        .tos                 = packet[1],
        .ttl                 = carrier.ttl,
        .type                = echo[0],
        .code                = echo[1],
    };
    if (echo[1] != 0)
    {
        envelope_out->error_reason = "unsupported Echo code (zero required)";
        return kPingWireInboundInvalidCarrier;
    }
    if (echo[0] == reply_type)
    {
        /* Unmatched replies need no tunnel trailer or native geometry. */
        return kPingWireInboundEchoReply;
    }
    if (echo[0] != request_type)
    {
        envelope_out->error_reason = "unsupported carrier type (Echo Request or Echo Reply required)";
        return kPingWireInboundInvalidCarrier;
    }
    if (envelope_out->icmp_payload_length == 0)
    {
        envelope_out->error_reason = "Echo Request is missing its final protocol byte";
        return kPingWireInboundInvalidCarrier;
    }
    envelope_out->native_protocol    = packet[length - 1U];
    envelope_out->native_body_length = (uint16_t) (envelope_out->icmp_payload_length - 1U);
    if (! pingwireNativeShape(
            envelope_out->icmp_payload, envelope_out->native_body_length, envelope_out->native_protocol))
    {
        envelope_out->error_reason = "Echo Request has invalid native TCP, UDP, or ICMP geometry";
        return kPingWireInboundInvalidCarrier;
    }
    return kPingWireInboundEchoRequest;
}

ping_wire_inbound_kind_t pingwireParseInbound(const uint8_t *packet, uint32_t length, const ping_wire_config_t *config,
                                              ping_wire_envelope_t *envelope_out)
{
    if (config == NULL)
    {
        if (envelope_out != NULL)
        {
            memoryZero(envelope_out, sizeof(*envelope_out));
            envelope_out->error_reason = "invalid Echo parser arguments";
        }
        return kPingWireInboundMalformed;
    }
    return pingwireParseEcho(packet, length, IP_PROTO_ICMP, ICMP_ECHO, ICMP_ER, 0, envelope_out);
}

bool pingwireBuildReply(sbuf_t *buf, const ping_wire_envelope_t *request, uint16_t ipv4_identification,
                        uint8_t protocol, uint8_t request_type, uint8_t reply_type, uint32_t checksum_seed)
{
    if (buf == NULL || request == NULL || request->type != request_type || request->code != 0 ||
        request->total_length != sbufGetLength(buf))
    {
        return false;
    }
    ipv4_packet_view_t carrier = {0};
    uint8_t           *packet  = sbufGetMutablePtr(buf);
    if (pingwireIpv4PacketErrorWithView(packet, sbufGetLength(buf), &carrier) != NULL || carrier.fragmented ||
        carrier.protocol != protocol || carrier.ip_header_length != request->ip_header_length ||
        carrier.transport_length < kPingWireIcmpHeaderLength + 1 || sbufGetLength(buf) > kMaxAllowedPacketLength)
    {
        return false;
    }
    struct ip_hdr *ip = (struct ip_hdr *) packet;
    ip->src.addr      = request->destination_ipv4;
    ip->dest.addr     = request->source_ipv4;
    IPH_ID_SET(ip, lwip_htons(ipv4_identification));
    IPH_TTL_SET(ip, 64);
    IPH_TOS_SET(ip, request->tos);
    IPH_OFFSET_SET(ip, 0);
    packet[carrier.transport_offset] = reply_type;
    const bool repaired              = pingwireRecalculateEchoChecksums(buf, protocol, checksum_seed);
    assert(repaired);
    discard repaired;
    sbufSetRecalculateChecksum(buf, false);
    return true;
}

bool pingwireBuildEchoReply(sbuf_t *buf, const ping_wire_config_t *config, const ping_wire_envelope_t *request,
                            uint16_t ipv4_identification)
{
    return config != NULL &&
           pingwireBuildReply(buf, request, ipv4_identification, IP_PROTO_ICMP, ICMP_ECHO, ICMP_ER, 0);
}

bool pingwireStripRequest(sbuf_t *buf, const ping_wire_envelope_t *request, uint8_t request_type)
{
    if (buf == NULL || request == NULL || request->type != request_type || request->code != 0 ||
        request->total_length != sbufGetLength(buf) || request->ip_header_length < IP_HLEN ||
        request->ip_header_length > IP_HLEN_MAX || request->icmp_payload_length == 0 ||
        request->icmp_payload_length != request->native_body_length + 1U ||
        request->total_length != request->ip_header_length + kPingWireIcmpHeaderLength + request->icmp_payload_length)
    {
        return false;
    }
    uint8_t *packet = sbufGetMutablePtr(buf);
    /* Save all envelope values before mutation: its payload pointer aliases buf. */
    const uint16_t header_length = request->ip_header_length;
    const uint16_t body_length   = request->native_body_length;
    const uint8_t  protocol      = request->native_protocol;
    const uint16_t total         = (uint16_t) (request->total_length - kPingWireEncapsulationOverhead);
    memmove(packet + header_length + kPingWireEncapsulationOverhead,
            packet + header_length + kPingWireIcmpHeaderLength,
            body_length);
    memmove(packet + kPingWireEncapsulationOverhead, packet, header_length);
    packet            = sbufShiftRight(buf, kPingWireEncapsulationOverhead);
    struct ip_hdr *ip = (struct ip_hdr *) packet;
    IPH_PROTO_SET(ip, protocol);
    IPH_LEN_SET(ip, lwip_htons(total));
    if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP)
    {
        const bool restored = updateIpv4TransportChecksumAddresses(
            packet, total, protocol, 0, 0, request->source_ipv4, request->destination_ipv4);
        assert(restored);
        discard restored;
    }
    const bool repaired = calcIpv4HeaderChecksum(packet, total);
    assert(repaired);
    discard repaired;
    sbufSetRecalculateChecksum(buf, false);
    return true;
}

bool pingwireStripEchoRequest(sbuf_t *buf, const ping_wire_envelope_t *request)
{
    return pingwireStripRequest(buf, request, ICMP_ECHO);
}

static bool pingwireDigestPayload(const uint8_t digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE], const uint8_t *payload,
                                  uint16_t payload_length, uint8_t digest[kPingWirePayloadDigestLength])
{
    if (digest_key == NULL || payload == NULL || digest == NULL)
    {
        return false;
    }

    return wCryptoBlake2s(digest,
                          kPingWirePayloadDigestLength,
                          digest_key,
                          WCRYPTO_BLAKE2S_MAX_KEY_SIZE,
                          payload,
                          payload_length) == kWCryptoOk;
}

ping_wire_tracker_t *pingwireTrackerCreate(void)
{
    ping_wire_tracker_t *tracker = memoryAllocateZero(sizeof(*tracker));

    if (! mutexTryInit(&tracker->outstanding_mutex))
    {
        goto fail;
    }
    tracker->outstanding_mutex_initialized = true;

    if (! mutexTryInit(&tracker->replay_mutex))
    {
        goto fail;
    }
    tracker->replay_mutex_initialized = true;
    return tracker;

fail:
    pingwireTrackerDestroy(tracker);
    return NULL;
}

void pingwireTrackerDestroy(ping_wire_tracker_t *tracker)
{
    if (tracker == NULL)
    {
        return;
    }

    if (tracker->replay_mutex_initialized)
    {
        mutexDestroy(&tracker->replay_mutex);
        tracker->replay_mutex_initialized = false;
    }
    if (tracker->outstanding_mutex_initialized)
    {
        mutexDestroy(&tracker->outstanding_mutex);
        tracker->outstanding_mutex_initialized = false;
    }

    memorySecureZero(tracker, sizeof(*tracker));
    memoryFree(tracker);
}

bool pingwireOutstandingRecord(ping_wire_tracker_t *tracker, const uint8_t digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE],
                               uint16_t identifier, uint16_t sequence, const uint8_t *payload, uint16_t payload_length)
{
    if (tracker == NULL || ! tracker->outstanding_mutex_initialized || payload_length == 0)
    {
        return false;
    }

    /* Calculate before overwriting a ring entry, then copy from a stack digest. */
    uint8_t digest[kPingWirePayloadDigestLength];
    if (! pingwireDigestPayload(digest_key, payload, payload_length, digest))
    {
        return false;
    }

    mutexLock(&tracker->outstanding_mutex);

    /* A wire identity can represent only one live request generation. */
    for (uint32_t i = 0; i < kPingWireOutstandingCapacity; ++i)
    {
        ping_wire_outstanding_entry_t *existing = &tracker->outstanding.entries[i];
        if (existing->occupied && existing->identifier == identifier && existing->sequence == sequence &&
            existing->payload_length == payload_length &&
            memorySecureEqual(existing->payload_digest, digest, sizeof(digest)))
        {
            memorySecureZero(existing, sizeof(*existing));
        }
    }

    const uint32_t index = tracker->outstanding.replacement_index;
    assert(index < kPingWireOutstandingCapacity);
    ping_wire_outstanding_entry_t *entry = &tracker->outstanding.entries[index];

    memorySecureZero(entry, sizeof(*entry));
    entry->identifier       = identifier;
    entry->sequence         = sequence;
    entry->payload_length   = payload_length;
    entry->occupied         = true;
    memoryCopy(entry->payload_digest, digest, sizeof(digest));

    tracker->outstanding.replacement_index = (index + 1U) % kPingWireOutstandingCapacity;
    mutexUnlock(&tracker->outstanding_mutex);
    memorySecureZero(digest, sizeof(digest));
    return true;
}

bool pingwireOutstandingConsumeForType(ping_wire_tracker_t        *tracker,
                                       const uint8_t               digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE],
                                       const ping_wire_envelope_t *reply, uint8_t expected_type)
{
    if (tracker == NULL || ! tracker->outstanding_mutex_initialized || reply == NULL || reply->type != expected_type ||
        reply->code != 0 || reply->icmp_payload_length == 0)
    {
        return false;
    }

    uint8_t digest[kPingWirePayloadDigestLength];
    if (! pingwireDigestPayload(digest_key, reply->icmp_payload, reply->icmp_payload_length, digest))
    {
        return false;
    }

    mutexLock(&tracker->outstanding_mutex);

    /* Search newest-to-oldest so an exact consume has deterministic ring semantics. */
    for (uint32_t offset = 1; offset <= kPingWireOutstandingCapacity; ++offset)
    {
        const uint32_t index = (tracker->outstanding.replacement_index + kPingWireOutstandingCapacity - offset) %
                               kPingWireOutstandingCapacity;
        ping_wire_outstanding_entry_t *entry = &tracker->outstanding.entries[index];
        if (! entry->occupied || entry->identifier != reply->identifier || entry->sequence != reply->sequence ||
            entry->payload_length != reply->icmp_payload_length ||
            ! memorySecureEqual(entry->payload_digest, digest, sizeof(digest)))
        {
            continue;
        }

        memorySecureZero(entry, sizeof(*entry));
        mutexUnlock(&tracker->outstanding_mutex);
        memorySecureZero(digest, sizeof(digest));
        return true;
    }

    mutexUnlock(&tracker->outstanding_mutex);
    memorySecureZero(digest, sizeof(digest));
    return false;
}

bool pingwireOutstandingConsume(ping_wire_tracker_t *tracker, const uint8_t digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE],
                                const ping_wire_envelope_t *reply)
{
    return pingwireOutstandingConsumeForType(tracker, digest_key, reply, ICMP_ER);
}

ping_wire_replay_result_t pingwireReplayMarkForType(ping_wire_tracker_t *tracker,
                                                    const uint8_t        digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE],
                                                    const ping_wire_envelope_t *request, uint8_t expected_type)
{
    if (tracker == NULL || ! tracker->replay_mutex_initialized || request == NULL || request->type != expected_type ||
        request->code != 0 || request->icmp_payload_length == 0)
    {
        return kPingWireReplayError;
    }

    uint8_t digest[kPingWirePayloadDigestLength];
    if (! pingwireDigestPayload(digest_key, request->icmp_payload, request->icmp_payload_length, digest))
    {
        return kPingWireReplayError;
    }

    mutexLock(&tracker->replay_mutex);

    for (uint32_t i = 0; i < kPingWireReplayCapacity; ++i)
    {
        const ping_wire_replay_entry_t *entry = &tracker->replay.entries[i];
        if (entry->occupied && entry->identifier == request->identifier && entry->sequence == request->sequence &&
            entry->payload_length == request->icmp_payload_length &&
            memorySecureEqual(entry->payload_digest, digest, sizeof(digest)))
        {
            mutexUnlock(&tracker->replay_mutex);
            memorySecureZero(digest, sizeof(digest));
            return kPingWireReplayDuplicate;
        }
    }

    const uint32_t index = tracker->replay.replacement_index;
    assert(index < kPingWireReplayCapacity);
    ping_wire_replay_entry_t *entry = &tracker->replay.entries[index];
    memorySecureZero(entry, sizeof(*entry));
    entry->identifier     = request->identifier;
    entry->sequence       = request->sequence;
    entry->payload_length = request->icmp_payload_length;
    entry->occupied       = true;
    memoryCopy(entry->payload_digest, digest, sizeof(digest));

    tracker->replay.replacement_index = (index + 1U) % kPingWireReplayCapacity;
    mutexUnlock(&tracker->replay_mutex);
    memorySecureZero(digest, sizeof(digest));
    return kPingWireReplayNew;
}

ping_wire_replay_result_t pingwireReplayMark(ping_wire_tracker_t        *tracker,
                                             const uint8_t               digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE],
                                             const ping_wire_envelope_t *request)
{
    return pingwireReplayMarkForType(tracker, digest_key, request, ICMP_ECHO);
}

static uint32_t pingwireXorShift32(uint32_t value)
{
    if (value == 0)
    {
        value = UINT32_C(0x6d2b79f5);
    }
    value ^= value << 13U;
    value ^= value >> 17U;
    value ^= value << 5U;
    return value == 0 ? UINT32_C(0x6d2b79f5) : value;
}

static uint32_t pingwireReplyIdRandom(ping_wire_reply_id_generator_t *generator)
{
    uint32_t observed = atomicLoadU32Relaxed(&generator->random_state);
    for (;;)
    {
        const uint32_t next = pingwireXorShift32(observed);
        if (atomicCompareExchangeU32Explicit(
                &generator->random_state, &observed, next, memory_order_relaxed, memory_order_relaxed))
        {
            return next;
        }
    }
}

void pingwireReplyIdGeneratorInitialize(ping_wire_reply_id_generator_t *generator, uint32_t seed, uint64_t now_ms)
{
    assert(generator != NULL);

    atomicStoreU32Relaxed(&generator->visible_counter, seed);
    atomicStoreU32Relaxed(&generator->random_state, pingwireXorShift32(seed ^ UINT32_C(0xa5c39e71)));
    atomicStoreU64Relaxed(&generator->last_reply_ms, now_ms);
}

uint16_t pingwireReplyIdGeneratorNextAt(ping_wire_reply_id_generator_t *generator, uint64_t now_ms,
                                        uint32_t idle_perturbation)
{
    assert(generator != NULL);

    uint64_t observed_ms = atomicLoadU64Relaxed(&generator->last_reply_ms);
    for (;;)
    {
        bool idle = false;
        if (now_ms > observed_ms)
        {
            idle = observed_ms != 0 && now_ms - observed_ms >= kPingWireReplyIdlePerturbationMs;
            if (atomicCompareExchangeU64Explicit(
                    &generator->last_reply_ms, &observed_ms, now_ms, memory_order_relaxed, memory_order_relaxed))
            {
                if (idle)
                {
                    const uint32_t perturbation = 1U + (idle_perturbation % (kPingWireReplyPerturbationMaximum + 1U));
                    discard        atomicAddU32(&generator->visible_counter, perturbation);
                }
                break;
            }
            continue;
        }
        break;
    }

    return (uint16_t) (atomicAddU32(&generator->visible_counter, 1U) + 1U);
}

uint16_t pingwireReplyIdGeneratorNext(ping_wire_reply_id_generator_t *generator, uint64_t now_ms)
{
    return pingwireReplyIdGeneratorNextAt(generator, now_ms, pingwireReplyIdRandom(generator));
}
