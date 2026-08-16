#include "devices/device_frag_settlement.h"

#include "devices/device_frag_affinity.h"
#include "devices/device_reader_session.h"

struct device_frag_claim_s
{
    /* Must be first: sbuf owns this through the generic lifetime interface. */
    sbuf_lifetime_t lifetime;
    atomic_uint     refcount;
    /*
     * Low bits contain the latest factual settlement and the high bit is a
     * sticky Unknown observation. Resolver updates happen before their release
     * of a claim reference; the final acquire/release decrement observes every
     * completed update without allocating an OS-backed mutex per packet.
     */
    atomic_uint observation;

    device_reader_session_t           *session;
    device_frag_affinity_publication_t publication;
    uint32_t                           generation;
    uint32_t                           source;
    uint32_t                           destination;
    uint16_t                           identification;
    uint8_t                            protocol;
};

enum
{
    kDeviceFragObservationSettlementMask = 0x3U,
    kDeviceFragObservationUnknown        = 0x4U,
};

static device_frag_claim_t *deviceFragClaimFromLifetime(sbuf_lifetime_t *lifetime)
{
    return (device_frag_claim_t *) lifetime;
}

static bool deviceFragLifetimeIsClaim(const sbuf_lifetime_t *lifetime);

static bool deviceFragClaimMatchesGeneration(const device_frag_claim_t *claim)
{
    return claim->generation == (uint32_t) atomicLoadRelaxed(&claim->session->generation);
}

static bool deviceFragClaimReadKey(const sbuf_t *buf, uint32_t *source, uint32_t *destination, uint8_t *protocol,
                                   uint16_t *identification)
{
    const uint8_t *packet = sbufGetRawPtr(buf);
    const uint32_t length = sbufGetLength(buf);

    if (length < 20 || (packet[0] >> 4U) != 4 || (GET_BE16(packet + 6) & UINT16_C(0x3FFF)) == 0)
    {
        return false;
    }

    *source         = GET_BE32(packet + 12);
    *destination    = GET_BE32(packet + 16);
    *protocol       = packet[9];
    *identification = GET_BE16(packet + 4);
    return true;
}

static void deviceFragClaimRetainLifetime(sbuf_lifetime_t *lifetime)
{
    device_frag_claim_t  *claim    = deviceFragClaimFromLifetime(lifetime);
    w_atomic_uint_value_t previous = atomicLoadRelaxed(&claim->refcount);

    for (;;)
    {
        if (UNLIKELY(previous == 0 || previous >= W_ATOMIC_UINT_VALUE_MAX))
        {
            LOGF("DeviceFragClaim: reference count overflow or resurrection");
            abortProgramNow(1);
        }
        if (atomic_compare_exchange_weak_explicit(
                &claim->refcount, &previous, previous + 1, memory_order_relaxed, memory_order_relaxed))
        {
            return;
        }
    }
}

static void deviceFragClaimReleaseFinal(device_frag_claim_t *claim)
{
    const unsigned int observation = atomic_load_explicit(&claim->observation, memory_order_relaxed);
    deviceFragAffinitySettlePublication(
        claim->session->frag_affinity,
        &claim->publication,
        (observation & kDeviceFragObservationUnknown) != 0
            ? kDeviceFragSettlementUnknown
            : (device_frag_settlement_t) (observation & kDeviceFragObservationSettlementMask));
    deviceReaderSessionUnref(claim->session);
    memoryFree(claim);
}

static void deviceFragClaimUnref(device_frag_claim_t *claim)
{
    const w_atomic_uint_value_t previous = atomicSubExplicit(&claim->refcount, 1, memory_order_acq_rel);
    assert(previous > 0);
    if (previous == 1)
    {
        deviceFragClaimReleaseFinal(claim);
    }
}

static void deviceFragClaimReleaseLifetime(sbuf_lifetime_t *lifetime)
{
    device_frag_claim_t *claim = deviceFragClaimFromLifetime(lifetime);

    discard atomic_fetch_or_explicit(&claim->observation, kDeviceFragObservationUnknown, memory_order_relaxed);
    deviceFragClaimUnref(claim);
}

static bool deviceFragLifetimeIsClaim(const sbuf_lifetime_t *lifetime)
{
    return lifetime != NULL && lifetime->retain == deviceFragClaimRetainLifetime &&
           lifetime->release == deviceFragClaimReleaseLifetime;
}

bool deviceFragClaimAttach(device_reader_session_t *session, uint32_t generation,
                           const device_frag_affinity_publication_t *publication, sbuf_t *buf)
{
    assert(session != NULL && publication != NULL && publication->valid && buf != NULL);
    assert(sbufGetLifetime(buf) == NULL);

    uint32_t source;
    uint32_t destination;
    uint16_t identification;
    uint8_t  protocol;
    if (UNLIKELY(! deviceFragClaimReadKey(buf, &source, &destination, &protocol, &identification)))
    {
        return false;
    }

    device_frag_claim_t *claim = memoryAllocate(sizeof(*claim));
    if (UNLIKELY(claim == NULL))
    {
        return false;
    }

    *claim = (device_frag_claim_t) {
        .lifetime       = {.retain = deviceFragClaimRetainLifetime, .release = deviceFragClaimReleaseLifetime},
        .refcount       = 1,
        .session        = session,
        .publication    = *publication,
        .generation     = generation,
        .source         = source,
        .destination    = destination,
        .identification = identification,
        .protocol       = protocol,
    };
    atomic_init(&claim->refcount, 1);
    atomic_init(&claim->observation, (unsigned int) kDeviceFragSettlementUnknown);
    deviceReaderSessionRef(session);
    sbufAttachLifetime(buf, &claim->lifetime);
    return true;
}

bool deviceFragClaimPacketMatches(const sbuf_t *buf)
{
    const sbuf_lifetime_t *lifetime = sbufGetLifetime(buf);
    if (! deviceFragLifetimeIsClaim(lifetime))
    {
        return true;
    }

    uint32_t source;
    uint32_t destination;
    uint16_t identification;
    uint8_t  protocol;
    if (! deviceFragClaimReadKey(buf, &source, &destination, &protocol, &identification))
    {
        return false;
    }

    const device_frag_claim_t *claim = (const device_frag_claim_t *) lifetime;
    return source == claim->source && destination == claim->destination && protocol == claim->protocol &&
           identification == claim->identification;
}

bool deviceFragClaimMayEnterStack(const sbuf_t *buf)
{
    const sbuf_lifetime_t *lifetime = sbufGetLifetime(buf);
    if (! deviceFragLifetimeIsClaim(lifetime))
    {
        return true;
    }

    const device_frag_claim_t *claim = (const device_frag_claim_t *) lifetime;
    return deviceFragClaimMatchesGeneration(claim) &&
           deviceFragAffinityPublicationMayEnter(claim->session->frag_affinity, &claim->publication);
}

static bool deviceFragClaimBeginStackUseInternal(device_frag_claim_t *claim)
{
    if (claim == NULL)
    {
        return true;
    }

    if (! deviceLifetimeGateEnter(&claim->session->delivery_gate))
    {
        return false;
    }
    if (! deviceFragClaimMatchesGeneration(claim) ||
        ! deviceFragAffinityPublicationMayEnter(claim->session->frag_affinity, &claim->publication))
    {
        deviceLifetimeGateLeave(&claim->session->delivery_gate);
        return false;
    }

    return true;
}

bool deviceFragClaimBeginStackUse(const sbuf_t *buf, device_frag_claim_t **claim_out)
{
    assert(claim_out != NULL);
    *claim_out = NULL;

    const sbuf_lifetime_t *lifetime = sbufGetLifetime(buf);
    if (! deviceFragLifetimeIsClaim(lifetime))
    {
        return true;
    }

    device_frag_claim_t *claim = (device_frag_claim_t *) lifetime;
    if (! deviceFragClaimBeginStackUseInternal(claim))
    {
        return false;
    }

    *claim_out = claim;
    return true;
}

bool deviceFragClaimBeginTakenStackUse(device_frag_claim_t *claim)
{
    return deviceFragClaimBeginStackUseInternal(claim);
}

void deviceFragClaimEndStackUse(device_frag_claim_t *claim)
{
    if (claim != NULL)
    {
        deviceLifetimeGateLeave(&claim->session->delivery_gate);
    }
}

device_frag_claim_t *deviceFragClaimTake(sbuf_t *buf)
{
    sbuf_lifetime_t *lifetime = sbufGetLifetime(buf);
    if (! deviceFragLifetimeIsClaim(lifetime))
    {
        return NULL;
    }

    discard sbufTakeLifetime(buf);
    return deviceFragClaimFromLifetime(lifetime);
}

void deviceFragClaimResolve(device_frag_claim_t *claim, device_frag_settlement_t settlement)
{
    if (claim == NULL)
    {
        return;
    }

    if (settlement == kDeviceFragSettlementUnknown)
    {
        discard atomic_fetch_or_explicit(&claim->observation, kDeviceFragObservationUnknown, memory_order_relaxed);
    }
    else
    {
        /*
         * Publish the latest factual stack observation without ever erasing an
         * Unknown bit concurrently made sticky by another copy.
         */
        unsigned int observed = atomic_load_explicit(&claim->observation, memory_order_relaxed);
        unsigned int desired;
        do
        {
            desired = (observed & ~kDeviceFragObservationSettlementMask) | (unsigned int) settlement;
        } while (! atomic_compare_exchange_weak_explicit(
            &claim->observation, &observed, desired, memory_order_relaxed, memory_order_relaxed));
    }
    deviceFragClaimUnref(claim);
}

void deviceFragClaimResolveBuffer(sbuf_t *buf, device_frag_settlement_t settlement)
{
    deviceFragClaimResolve(deviceFragClaimTake(buf), settlement);
}
