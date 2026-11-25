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
