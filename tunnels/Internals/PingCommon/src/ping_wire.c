#include "PingCommon/ping_wire.h"

/*
 * The implementation keeps all values in network byte order while they are
 * packet fields.  Correlation state stores host-order ICMP integers, but keeps
 * IPv4 addresses in the wire representation used by lwIP's packed headers.
 */

static bool pingwireIpv4ChecksumIsValid(const uint8_t *packet, uint16_t header_length)
{
    return inet_chksum(packet, header_length) == 0;
}

static bool pingwireIcmpChecksumIsValid(const uint8_t *packet, uint16_t length)
{
    return inet_chksum(packet, length) == 0;
}

bool pingwireIsExactIpv4Packet(const uint8_t *packet, uint32_t length)
{
    ipv4_packet_view_t view = {0};

    return packet != NULL && ipv4packetviewParse(packet, length, &view) && view.ip_total_length == length;
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

static bool pingwireOuterIpv4IsExact(const uint8_t *packet, uint32_t length, ipv4_packet_view_t *view_out)
{
    if (packet == NULL || view_out == NULL || length > kMaxAllowedPacketLength ||
        ! ipv4packetviewParse(packet, length, view_out) || view_out->ip_total_length != length ||
        view_out->ip_header_length != kPingWireIpv4HeaderLength)
    {
        return false;
    }

    return pingwireIpv4ChecksumIsValid(packet, view_out->ip_header_length);
}

ping_wire_inbound_kind_t pingwireParseInbound(const uint8_t *packet, uint32_t length, const ping_wire_config_t *config,
                                              ping_wire_envelope_t *envelope_out)
{
    if (envelope_out != NULL)
    {
        memoryZero(envelope_out, sizeof(*envelope_out));
    }

    if (config == NULL || packet == NULL || envelope_out == NULL)
    {
        return kPingWireInboundMalformed;
    }

    ipv4_packet_view_t outer = {0};
    if (! pingwireOuterIpv4IsExact(packet, length, &outer))
    {
        return kPingWireInboundMalformed;
    }

    if (outer.source_address != config->peer_ipv4 || outer.destination_address != config->local_ipv4 ||
        outer.protocol != IP_PROTO_ICMP)
    {
        return kPingWireInboundUnrelated;
    }

    if (outer.fragmented || outer.transport_length < kPingWireIcmpHeaderLength)
    {
        return kPingWireInboundInvalidCarrier;
    }

    const uint8_t              *icmp_bytes = packet + outer.transport_offset;
    const struct icmp_echo_hdr *icmp       = (const struct icmp_echo_hdr *) icmp_bytes;
    if (! pingwireIcmpChecksumIsValid(icmp_bytes, outer.transport_length))
    {
        return kPingWireInboundInvalidCarrier;
    }

    *envelope_out = (ping_wire_envelope_t) {
        .icmp_payload        = icmp_bytes + kPingWireIcmpHeaderLength,
        .inner_ipv4          = icmp_bytes + kPingWireIcmpHeaderLength,
        .source_ipv4         = outer.source_address,
        .destination_ipv4    = outer.destination_address,
        .total_length        = outer.ip_total_length,
        .icmp_payload_length = (uint16_t) (outer.transport_length - kPingWireIcmpHeaderLength),
        .inner_ipv4_length   = (uint16_t) (outer.transport_length - kPingWireIcmpHeaderLength),
        .identifier          = lwip_ntohs(icmp->id),
        .sequence            = lwip_ntohs(icmp->seqno),
        .tos                 = IPH_TOS((const struct ip_hdr *) packet),
        .ttl                 = outer.ttl,
        .type                = icmp->type,
        .code                = icmp->code,
    };

    if (icmp->code != 0)
    {
        return kPingWireInboundInvalidCarrier;
    }

    if (icmp->type == ICMP_ECHO)
    {
        if (! pingwireIsExactIpv4Packet(envelope_out->inner_ipv4, envelope_out->inner_ipv4_length))
        {
            return kPingWireInboundInvalidCarrier;
        }
        return kPingWireInboundEchoRequest;
    }

    if (icmp->type == ICMP_ER)
    {
        return kPingWireInboundEchoReply;
    }

    return kPingWireInboundInvalidCarrier;
}

bool pingwireEchoRequestPreflight(const sbuf_t *buf)
{
    return buf != NULL && pingwireIsExactIpv4Packet(sbufGetRawPtr(buf), sbufGetLength(buf)) &&
           sbufGetLength(buf) <= kPingWireMaxInnerPacketLength &&
           sbufGetLeftCapacity(buf) >= kPingWireEncapsulationOverhead;
}

bool pingwireBuildEchoRequest(sbuf_t *buf, const ping_wire_config_t *config, uint16_t sequence)
{
    if (config == NULL || ! pingwireEchoRequestPreflight(buf))
    {
        return false;
    }

    const uint32_t total_length = sbufGetLength(buf) + kPingWireEncapsulationOverhead;
    assert(total_length <= kMaxAllowedPacketLength);

    sbufShiftLeft(buf, kPingWireEncapsulationOverhead);

    uint8_t              *packet = sbufGetMutablePtr(buf);
    struct ip_hdr        *ip     = (struct ip_hdr *) packet;
    struct icmp_echo_hdr *icmp   = (struct icmp_echo_hdr *) (packet + kPingWireIpv4HeaderLength);

    memoryZero(packet, kPingWireEncapsulationOverhead);
    IPH_VHL_SET(ip, 4, kPingWireIpv4HeaderLength / 4U);
    IPH_TOS_SET(ip, config->tos);
    IPH_LEN_SET(ip, lwip_htons((uint16_t) total_length));
    IPH_ID_SET(ip, 0);
    IPH_OFFSET_SET(ip, lwip_htons(IP_DF));
    IPH_TTL_SET(ip, config->ttl);
    IPH_PROTO_SET(ip, IP_PROTO_ICMP);
    IPH_CHKSUM_SET(ip, 0);
    ip->src.addr  = config->local_ipv4;
    ip->dest.addr = config->peer_ipv4;

    ICMPH_TYPE_SET(icmp, ICMP_ECHO);
    ICMPH_CODE_SET(icmp, 0);
    icmp->chksum = 0;
    icmp->id     = lwip_htons(config->identifier);
    icmp->seqno  = lwip_htons(sequence);

    return calcFullPacketChecksum(packet, total_length);
}

bool pingwireBuildEchoReply(sbuf_t *buf, const ping_wire_config_t *config, const ping_wire_envelope_t *request,
                            uint16_t ipv4_identification)
{
    if (buf == NULL || config == NULL || request == NULL || request->type != ICMP_ECHO || request->code != 0 ||
        request->total_length != sbufGetLength(buf) || request->total_length < kPingWireEncapsulationOverhead)
    {
        return false;
    }

    uint8_t              *packet = sbufGetMutablePtr(buf);
    struct ip_hdr        *ip     = (struct ip_hdr *) packet;
    struct icmp_echo_hdr *icmp   = (struct icmp_echo_hdr *) (packet + kPingWireIpv4HeaderLength);

    if (! pingwireIsExactIpv4Packet(packet, sbufGetLength(buf)) || IPH_HL_BYTES(ip) != kPingWireIpv4HeaderLength ||
        IPH_PROTO(ip) != IP_PROTO_ICMP)
    {
        return false;
    }

    /* The request clone retains every ICMP payload byte and both ICMP fields. */
    IPH_VHL_SET(ip, 4, kPingWireIpv4HeaderLength / 4U);
    IPH_TOS_SET(ip, request->tos);
    IPH_LEN_SET(ip, lwip_htons(request->total_length));
    IPH_ID_SET(ip, lwip_htons(ipv4_identification));
    IPH_OFFSET_SET(ip, 0);
    IPH_TTL_SET(ip, config->ttl);
    IPH_PROTO_SET(ip, IP_PROTO_ICMP);
    IPH_CHKSUM_SET(ip, 0);
    ip->src.addr  = config->local_ipv4;
    ip->dest.addr = config->peer_ipv4;

    ICMPH_TYPE_SET(icmp, ICMP_ER);
    ICMPH_CODE_SET(icmp, 0);
    icmp->chksum = 0;

    return calcFullPacketChecksum(packet, request->total_length);
}

bool pingwireStripEchoRequest(sbuf_t *buf, const ping_wire_envelope_t *request)
{
    if (buf == NULL || request == NULL || request->type != ICMP_ECHO || request->code != 0 ||
        request->total_length != sbufGetLength(buf) || request->inner_ipv4_length == 0 ||
        request->inner_ipv4_length != request->icmp_payload_length ||
        request->total_length != (uint16_t) (kPingWireEncapsulationOverhead + request->inner_ipv4_length))
    {
        return false;
    }

    sbufShiftRight(buf, kPingWireEncapsulationOverhead);
    sbufSetLength(buf, request->inner_ipv4_length);
    return true;
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
    if (tracker == NULL)
    {
        return NULL;
    }

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
                               uint16_t identifier, uint16_t sequence, uint32_t reply_source_ipv4,
                               uint32_t reply_destination_ipv4, const uint8_t *payload, uint16_t payload_length)
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
        if (existing->occupied && existing->source_ipv4 == reply_source_ipv4 &&
            existing->destination_ipv4 == reply_destination_ipv4 && existing->identifier == identifier &&
            existing->sequence == sequence && existing->payload_length == payload_length &&
            memorySecureEqual(existing->payload_digest, digest, sizeof(digest)))
        {
            memorySecureZero(existing, sizeof(*existing));
        }
    }

    const uint32_t index = tracker->outstanding.replacement_index;
    assert(index < kPingWireOutstandingCapacity);
    ping_wire_outstanding_entry_t *entry = &tracker->outstanding.entries[index];

    memorySecureZero(entry, sizeof(*entry));
    entry->source_ipv4      = reply_source_ipv4;
    entry->destination_ipv4 = reply_destination_ipv4;
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

bool pingwireOutstandingConsume(ping_wire_tracker_t *tracker, const uint8_t digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE],
                                const ping_wire_envelope_t *reply)
{
    if (tracker == NULL || ! tracker->outstanding_mutex_initialized || reply == NULL || reply->type != ICMP_ER ||
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
        if (! entry->occupied || entry->source_ipv4 != reply->source_ipv4 ||
            entry->destination_ipv4 != reply->destination_ipv4 || entry->identifier != reply->identifier ||
            entry->sequence != reply->sequence || entry->payload_length != reply->icmp_payload_length ||
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

ping_wire_replay_result_t pingwireReplayMark(ping_wire_tracker_t        *tracker,
                                             const uint8_t               digest_key[WCRYPTO_BLAKE2S_MAX_KEY_SIZE],
                                             const ping_wire_envelope_t *request)
{
    if (tracker == NULL || ! tracker->replay_mutex_initialized || request == NULL || request->type != ICMP_ECHO ||
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
    w_atomic_uint_value_t observed = atomicLoadRelaxed(&generator->random_state);
    for (;;)
    {
        const uint32_t next = pingwireXorShift32((uint32_t) observed);
        if (atomicCompareExchangeExplicit(&generator->random_state,
                                          &observed,
                                          (w_atomic_uint_value_t) next,
                                          memory_order_relaxed,
                                          memory_order_relaxed))
        {
            return next;
        }
    }
}

void pingwireReplyIdGeneratorInitialize(ping_wire_reply_id_generator_t *generator, uint32_t seed, uint64_t now_ms)
{
    assert(generator != NULL);

    atomicStoreRelaxed(&generator->visible_counter, seed);
    atomicStoreRelaxed(&generator->random_state, pingwireXorShift32(seed ^ UINT32_C(0xa5c39e71)));
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
                    discard        atomicAdd(&generator->visible_counter, perturbation);
                }
                break;
            }
            continue;
        }
        break;
    }

    return (uint16_t) (atomicAdd(&generator->visible_counter, 1U) + 1U);
}

uint16_t pingwireReplyIdGeneratorNext(ping_wire_reply_id_generator_t *generator, uint64_t now_ms)
{
    return pingwireReplyIdGeneratorNextAt(generator, now_ms, pingwireReplyIdRandom(generator));
}
