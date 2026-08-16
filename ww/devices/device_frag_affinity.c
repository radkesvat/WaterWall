#include "devices/device_frag_affinity.h"

#include "devices/device_flow_affinity.h"
#include "loggers/internal_logger.h"
#include "loggers/log_rate_limiter.h"
#include "wchecksum.h"

#include "lwip/inet_chksum.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/udp.h"

enum
{
    kDeviceFragAffinityIpv4MoreFragments = 0x2000,
    kDeviceFragAffinityIpv4OffsetMask    = 0x1FFF,
    kDeviceFragAffinityLogIntervalMs     = 5U * 1000U,
    kDeviceFragAffinityMaxPayloadEnd     = UINT16_MAX - 20U
};

static atomic_log_rate_limiter_t g_frag_affinity_full_log;

typedef struct device_frag_range_s
{
    uint32_t begin;
    uint32_t end;
} device_frag_range_t;

typedef struct device_staged_frag_s
{
    sbuf_t  *buf;
    uint32_t offset;
    uint16_t payload_len;
    bool     more_fragments;
} device_staged_frag_t;

/*
 * A released identity that may still have a prefix inside reassembly.
 *
 * Deliberately not an association: no staged buffers, no coverage ranges, no
 * publication accounting. Holding the full association for a reassembly lifetime
 * would let ordinary refusals consume the association table.
 */
typedef struct device_frag_quarantine_s
{
    uint32_t src;
    uint32_t dst;
    uint16_t ident;
    uint8_t  proto;
    bool     in_use;
    uint64_t expires_at_ms;
    uint32_t release_epoch;
} device_frag_quarantine_t;

typedef struct device_frag_quarantine_sweep_s
{
    uint16_t free_slots[kDeviceFragAffinityMaxQuarantine];
    uint16_t free_count;
    uint16_t next_free;
} device_frag_quarantine_sweep_t;

typedef struct device_frag_affinity_entry_s
{
    uint32_t src;
    uint32_t dst;
    uint16_t ident;
    uint8_t  proto;
    uint64_t serial;

    bool in_use;
    bool poisoned;
    bool completion_pending;
    /* The last factual settlement describes the exact lwIP reassembly key. */
    bool     residue_known;
    bool     residue_present;
    bool     wid_known;
    wid_t    wid;
    uint64_t zero_flow_hash;

    uint64_t expires_at_ms;
    uint64_t residue_release_at_ms;
    uint32_t residue_release_epoch;
    uint32_t final_end;
    uint32_t pending_publications;
    bool     residue_barrier_armed;
    bool     saw_last;

    uint8_t             range_count;
    device_frag_range_t ranges[kDeviceFragAffinityMaxRanges];

    uint8_t              staged_count;
    device_staged_frag_t staged[kDeviceFragAffinityMaxStagedPerEntry];
} device_frag_affinity_entry_t;

struct device_frag_affinity_table_s
{
    buffer_pool_t *release_pool;
    wmutex_t       lock;

    /*
     * Whether a reader generation is open. Closed means every offer is consumed
     * and recycled without creating or modifying an association, which is what
     * stops an orphan tail - a fragment that yields no dispatch and therefore
     * never reaches the session's own admission check - from being staged after
     * End and adopted by the next generation's fragment zero.
     */
    bool generation_open;

    uint32_t staged_total;
    uint32_t staged_bytes;
    uint32_t quarantine_count;
    uint64_t next_expiry_ms;
    uint64_t next_serial;

    sbuf_t *release_scratch[kDeviceFragAffinityMaxStagedPerEntry];

    device_frag_affinity_entry_t entries[kDeviceFragAffinityMaxEntries];
    device_frag_quarantine_t     quarantine[kDeviceFragAffinityMaxQuarantine];
};

typedef struct device_frag_view_s
{
    uint32_t src;
    uint32_t dst;
    uint16_t ident;
    uint16_t offset;
    uint16_t payload_len;
    uint8_t  proto;
    bool     more_fragments;
} device_frag_view_t;

typedef enum device_frag_parse_result_e
{
    kDeviceFragParseNotFragment,
    kDeviceFragParseInvalid,
    kDeviceFragParseValid
} device_frag_parse_result_t;

static uint16_t deviceIpv4HeaderChecksum(const uint8_t *packet, uint32_t header_len)
{
    uint32_t sum = 0;

    for (uint32_t i = 0; i < header_len; i += 2U)
    {
        sum += GET_BE16(packet + i);
    }
    while ((sum >> 16U) != 0)
    {
        sum = (sum & UINT32_C(0xFFFF)) + (sum >> 16U);
    }
    return (uint16_t) ~sum;
}

static bool deviceIpv4NormalizeHeaderChecksum(uint8_t *packet, uint32_t length)
{
    if (packet == NULL || length < 20 || (packet[0] >> 4U) != 4)
    {
        return false;
    }

    const uint32_t header_len = (uint32_t) (packet[0] & 0x0FU) * 4U;
    if (header_len < 20 || header_len > 60 || header_len > length || GET_BE16(packet + 2) != length)
    {
        return false;
    }

    PUT_BE16(packet + 10, 0);
    PUT_BE16(packet + 10, deviceIpv4HeaderChecksum(packet, header_len));
    return true;
}

static bool deviceIpv4HeaderChecksumValid(const uint8_t *packet, uint32_t header_len)
{
    return deviceIpv4HeaderChecksum(packet, header_len) == 0;
}

static bool deviceIpv4TransportChecksumValid(const uint8_t *packet, uint32_t length, uint32_t header_len,
                                             uint8_t protocol)
{
    const uint16_t transport_len = (uint16_t) (length - header_len);
    const uint8_t *transport     = packet + header_len;
    ip4_addr_t     source;
    ip4_addr_t     destination;

    memoryCopy(&source.addr, packet + 12, sizeof(source.addr));
    memoryCopy(&destination.addr, packet + 16, sizeof(destination.addr));

    if (protocol == IP_PROTO_TCP)
    {
        if (transport_len < TCP_HLEN || ((uint32_t) (transport[12] >> 4U) * 4U) < TCP_HLEN ||
            ((uint32_t) (transport[12] >> 4U) * 4U) > transport_len)
        {
            return false;
        }
    }
    else if (protocol == IP_PROTO_UDP)
    {
        if (transport_len < UDP_HLEN || GET_BE16(transport + 4) != transport_len)
        {
            return false;
        }
        if (GET_BE16(transport + 6) == 0)
        {
            return true;
        }
    }
    else
    {
        return true;
    }

    struct pbuf transport_pbuf = {
        .next    = NULL,
        .payload = (void *) transport,
        .tot_len = transport_len,
        .len     = transport_len,
        .ref     = 1,
    };
    return inet_chksum_pseudo(&transport_pbuf, protocol, transport_len, &source, &destination) == 0;
}

bool deviceIpv4PreparePacketChecksums(uint8_t *packet, uint32_t length, device_packet_checksum_provenance_t provenance)
{
    if (packet == NULL || length == 0)
    {
        return false;
    }
    if ((packet[0] >> 4U) != 4)
    {
        return true;
    }
    if (length < 20)
    {
        return false;
    }

    const uint32_t header_len = (uint32_t) (packet[0] & 0x0FU) * 4U;
    if (header_len < 20 || header_len > 60 || header_len > length || GET_BE16(packet + 2) != length)
    {
        return false;
    }

    const uint8_t  protocol      = packet[9];
    const uint16_t fragment_bits = GET_BE16(packet + 6);
    const bool     fragmented =
        (fragment_bits & (kDeviceFragAffinityIpv4MoreFragments | kDeviceFragAffinityIpv4OffsetMask)) != 0;
    const device_ipv4_checksum_provenance_t transport_provenance =
        protocol == IP_PROTO_TCP ? provenance.tcp
                                 : (protocol == IP_PROTO_UDP ? provenance.udp : kDeviceIpv4ChecksumProvenValid);

    /* Validate every untrusted field before any trusted offload field is repaired. */
    if (provenance.ipv4 == kDeviceIpv4ChecksumUntrusted && ! deviceIpv4HeaderChecksumValid(packet, header_len))
    {
        return false;
    }
    if (! fragmented && transport_provenance == kDeviceIpv4ChecksumUntrusted &&
        ! deviceIpv4TransportChecksumValid(packet, length, header_len, protocol))
    {
        return false;
    }

    if (fragmented)
    {
        if (transport_provenance == kDeviceIpv4ChecksumOffloadNotReady)
        {
            return false;
        }
        return provenance.ipv4 != kDeviceIpv4ChecksumOffloadNotReady ||
               deviceIpv4NormalizeHeaderChecksum(packet, length);
    }

    if (transport_provenance == kDeviceIpv4ChecksumOffloadNotReady)
    {
        return calcFullPacketChecksum(packet, length);
    }
    if (provenance.ipv4 == kDeviceIpv4ChecksumOffloadNotReady)
    {
        return calcIpv4HeaderChecksum(packet, length);
    }
    return true;
}

device_packet_checksum_validity_t deviceIpv4ChecksumValidity(const uint8_t *packet, uint32_t length)
{
    device_packet_checksum_validity_t validity = {0};

    if (packet == NULL || length < 20 || (packet[0] >> 4U) != 4)
    {
        return validity;
    }

    const uint32_t header_len = (uint32_t) (packet[0] & 0x0FU) * 4U;
    if (header_len < 20 || header_len > 60 || header_len > length || GET_BE16(packet + 2) != length)
    {
        return validity;
    }

    validity.ipv4 = deviceIpv4HeaderChecksumValid(packet, header_len);

    /* One fragment never carries the whole transport checksum's input. */
    const uint16_t fragment_bits = GET_BE16(packet + 6);
    if ((fragment_bits & (kDeviceFragAffinityIpv4MoreFragments | kDeviceFragAffinityIpv4OffsetMask)) != 0)
    {
        return validity;
    }

    const uint8_t protocol = packet[9];
    if (protocol != IP_PROTO_TCP && protocol != IP_PROTO_UDP)
    {
        return validity;
    }

    const bool transport_valid = deviceIpv4TransportChecksumValid(packet, length, header_len, protocol);
    validity.tcp               = transport_valid && protocol == IP_PROTO_TCP;
    validity.udp               = transport_valid && protocol == IP_PROTO_UDP;
    return validity;
}

static device_frag_parse_result_t deviceFragAffinityParse(const uint8_t *packet, uint32_t length,
                                                          device_frag_view_t *out)
{
    if (packet == NULL || length < 20 || (packet[0] >> 4U) != 4)
    {
        return kDeviceFragParseNotFragment;
    }

    const uint16_t fragment_field = GET_BE16(packet + 6);
    if ((fragment_field & (kDeviceFragAffinityIpv4MoreFragments | kDeviceFragAffinityIpv4OffsetMask)) == 0)
    {
        return kDeviceFragParseNotFragment;
    }

    /* Preserve the association key even for a malformed fragment. */
    out->src            = GET_BE32(packet + 12);
    out->dst            = GET_BE32(packet + 16);
    out->proto          = packet[9];
    out->ident          = GET_BE16(packet + 4);
    out->offset         = (uint16_t) ((fragment_field & kDeviceFragAffinityIpv4OffsetMask) * 8U);
    out->more_fragments = (fragment_field & kDeviceFragAffinityIpv4MoreFragments) != 0;

    const uint32_t ip_header_len = (uint32_t) (packet[0] & 0x0FU) * 4U;
    const uint32_t ip_total_len  = GET_BE16(packet + 2);
    if (ip_header_len != 20 || ip_total_len <= ip_header_len || ip_total_len != length ||
        ! deviceIpv4HeaderChecksumValid(packet, ip_header_len))
    {
        return kDeviceFragParseInvalid;
    }

    out->payload_len = (uint16_t) (ip_total_len - ip_header_len);

    const uint32_t end = (uint32_t) out->offset + out->payload_len;
    if (out->payload_len == 0 || (out->more_fragments && (out->payload_len % 8U) != 0) ||
        end > (uint32_t) kDeviceFragAffinityMaxPayloadEnd)
    {
        return kDeviceFragParseInvalid;
    }

    return kDeviceFragParseValid;
}

static uint32_t deviceFragAffinityHome(const device_frag_view_t *view)
{
    uint64_t mixed = ((uint64_t) view->src << 32U) ^ (uint64_t) view->dst;

    mixed ^= ((uint64_t) view->ident << 8U) ^ (uint64_t) view->proto;
    mixed *= UINT64_C(0x9E3779B97F4A7C15);
    mixed ^= mixed >> 29U;
    return (uint32_t) (mixed % (uint64_t) kDeviceFragAffinityMaxEntries);
}

static bool deviceFragAffinityEntryMatches(const device_frag_affinity_entry_t *entry, const device_frag_view_t *view)
{
    return entry->in_use && entry->src == view->src && entry->dst == view->dst && entry->ident == view->ident &&
           entry->proto == view->proto;
}

static void deviceFragAffinityDropStaged(device_frag_affinity_table_t *table, device_frag_affinity_entry_t *entry)
{
    assert(table->release_pool != NULL || entry->staged_count == 0);
    for (uint8_t i = 0; i < entry->staged_count; ++i)
    {
        table->staged_bytes -= sbufGetLength(entry->staged[i].buf);
        bufferpoolReuseBuffer(table->release_pool, entry->staged[i].buf);
        entry->staged[i] = (device_staged_frag_t) {0};
    }

    table->staged_total -= entry->staged_count;
    entry->staged_count = 0;
}

static void deviceFragAffinityReleaseEntry(device_frag_affinity_table_t *table, device_frag_affinity_entry_t *entry)
{
    deviceFragAffinityDropStaged(table, entry);
    memorySet(entry, 0, sizeof(*entry));
}

/*
 * Marks the identity untrustworthy without touching the release pool.
 *
 * Split out because a generation boundary runs on the lifecycle thread while the
 * reader thread still owns the reader buffer pool. Metadata is safe to change
 * from there; returning a buffer to a thread-affine pool is not.
 */
static void deviceFragAffinityPoisonMetadata(device_frag_affinity_entry_t *entry)
{
    entry->poisoned              = true;
    entry->wid_known             = false;
    entry->range_count           = 0;
    entry->saw_last              = false;
    entry->final_end             = 0;
    entry->completion_pending    = false;
    entry->residue_known         = false;
    entry->residue_present       = false;
    entry->residue_barrier_armed = false;
    entry->residue_release_at_ms = 0;
    entry->residue_release_epoch = 0;
}

static void deviceFragAffinityPoison(device_frag_affinity_table_t *table, device_frag_affinity_entry_t *entry)
{
    deviceFragAffinityDropStaged(table, entry);
    deviceFragAffinityPoisonMetadata(entry);
}

// ---------------------------------------------------------------------------
// quarantine ring
// ---------------------------------------------------------------------------

static uint32_t deviceFragResidueReleaseEpoch(void)
{
    return ip4_reass_tmr_epoch() + (uint32_t) kDeviceFragAffinityResidueTimerPasses;
}

static bool deviceFragResidueEpochReached(uint32_t current_epoch, uint32_t release_epoch)
{
    /* Modular comparison is unambiguous because a barrier is only 16 passes
     * away, far below half of the uint32_t sequence space. */
    return (uint32_t) (current_epoch - release_epoch) < UINT32_C(0x80000000);
}

static bool deviceFragResidueBarrierReady(uint64_t now_ms, uint64_t expires_at_ms, uint32_t current_epoch,
                                          uint32_t release_epoch)
{
    return now_ms >= expires_at_ms && deviceFragResidueEpochReached(current_epoch, release_epoch);
}

static void deviceFragAffinityArmResidueBarrier(device_frag_affinity_entry_t *entry, uint64_t now_ms)
{
    entry->residue_release_at_ms = now_ms + (uint64_t) kDeviceFragAffinityResidueTimeoutMs;
    entry->residue_release_epoch = deviceFragResidueReleaseEpoch();
    entry->residue_barrier_armed = true;
}

static bool deviceFragQuarantineBlocks(device_frag_affinity_table_t *table, const device_frag_view_t *view,
                                       uint64_t now_ms)
{
    if (table->quarantine_count == 0)
    {
        return false;
    }

    const uint32_t current_epoch = ip4_reass_tmr_epoch();

    for (uint32_t i = 0; i < (uint32_t) kDeviceFragAffinityMaxQuarantine; ++i)
    {
        device_frag_quarantine_t *record = &table->quarantine[i];
        if (! record->in_use || record->src != view->src || record->dst != view->dst || record->ident != view->ident ||
            record->proto != view->proto)
        {
            continue;
        }
        if (deviceFragResidueBarrierReady(now_ms, record->expires_at_ms, current_epoch, record->release_epoch))
        {
            *record = (device_frag_quarantine_t) {0};
            --table->quarantine_count;
            return false;
        }
        return true;
    }
    return false;
}

/*
 * Takes an identity out of the association table and holds only its name and
 * its wall-clock/actual-timer-pass release barrier.
 *
 * Returns false when every record is still live. A live quarantine is never
 * evicted to make room for another one, so the caller keeps the poisoned
 * association in place instead - which is correct, just more expensive.
 */
static bool deviceFragQuarantineAdmit(device_frag_affinity_table_t *table, const device_frag_affinity_entry_t *entry,
                                      uint64_t now_ms)
{
    device_frag_quarantine_t *free_slot     = NULL;
    const uint32_t            current_epoch = ip4_reass_tmr_epoch();
    const uint64_t            release_at_ms = entry->residue_barrier_armed
                                                  ? entry->residue_release_at_ms
                                                  : now_ms + (uint64_t) kDeviceFragAffinityResidueTimeoutMs;
    const uint32_t            release_epoch = entry->residue_barrier_armed
                                                  ? entry->residue_release_epoch
                                                  : current_epoch + (uint32_t) kDeviceFragAffinityResidueTimerPasses;

    for (uint32_t i = 0; i < (uint32_t) kDeviceFragAffinityMaxQuarantine; ++i)
    {
        device_frag_quarantine_t *record = &table->quarantine[i];

        if (record->in_use && record->src == entry->src && record->dst == entry->dst && record->ident == entry->ident &&
            record->proto == entry->proto)
        {
            if (release_at_ms >= record->expires_at_ms)
            {
                record->expires_at_ms = release_at_ms;
                record->release_epoch = release_epoch;
            }
            return true;
        }

        if (! record->in_use)
        {
            free_slot = (free_slot != NULL) ? free_slot : record;
        }
        else if (deviceFragResidueBarrierReady(now_ms, record->expires_at_ms, current_epoch, record->release_epoch))
        {
            record->in_use = false;
            --table->quarantine_count;
            free_slot = (free_slot != NULL) ? free_slot : record;
        }
    }

    if (free_slot == NULL)
    {
        return false;
    }

    *free_slot = (device_frag_quarantine_t) {
        .src           = entry->src,
        .dst           = entry->dst,
        .ident         = entry->ident,
        .proto         = entry->proto,
        .in_use        = true,
        .expires_at_ms = release_at_ms,
        .release_epoch = release_epoch,
    };
    ++table->quarantine_count;
    return true;
}

static void deviceFragQuarantineSweep(device_frag_affinity_table_t *table, uint64_t now_ms,
                                      device_frag_quarantine_sweep_t *sweep)
{
    const uint32_t current_epoch = ip4_reass_tmr_epoch();

    *sweep = (device_frag_quarantine_sweep_t) {0};

    for (uint32_t i = 0; i < (uint32_t) kDeviceFragAffinityMaxQuarantine; ++i)
    {
        device_frag_quarantine_t *record = &table->quarantine[i];
        if (record->in_use &&
            deviceFragResidueBarrierReady(now_ms, record->expires_at_ms, current_epoch, record->release_epoch))
        {
            record->in_use = false;
            --table->quarantine_count;
        }
        if (! record->in_use)
        {
            sweep->free_slots[sweep->free_count++] = (uint16_t) i;
        }
    }
}

/*
 * An identity cannot simultaneously be an association and a quarantine record:
 * every new association passes deviceFragQuarantineBlocks() while holding the
 * same table lock, and an association key is unique. The batch sweep can
 * therefore consume its one-pass free-slot inventory without repeating a
 * 512-record exact-key scan for each association.
 */
static bool deviceFragQuarantineAdmitSwept(device_frag_affinity_table_t       *table,
                                           const device_frag_affinity_entry_t *entry,
                                           device_frag_quarantine_sweep_t     *sweep)
{
    if (sweep->next_free >= sweep->free_count)
    {
        return false;
    }

    device_frag_quarantine_t *record = &table->quarantine[sweep->free_slots[sweep->next_free++]];
    assert(! record->in_use);
    assert(entry->residue_barrier_armed);
    *record = (device_frag_quarantine_t) {
        .src           = entry->src,
        .dst           = entry->dst,
        .ident         = entry->ident,
        .proto         = entry->proto,
        .in_use        = true,
        .expires_at_ms = entry->residue_release_at_ms,
        .release_epoch = entry->residue_release_epoch,
    };
    ++table->quarantine_count;
    return true;
}

static void deviceFragAffinityRefreshNextExpiry(device_frag_affinity_table_t *table)
{
    uint64_t earliest = UINT64_MAX;

    for (uint32_t i = 0; i < (uint32_t) kDeviceFragAffinityMaxEntries; ++i)
    {
        const device_frag_affinity_entry_t *entry = &table->entries[i];
        if (entry->in_use && entry->expires_at_ms < earliest)
        {
            earliest = entry->expires_at_ms;
        }
    }
    table->next_expiry_ms = earliest;
}

static void deviceFragAffinitySweep(device_frag_affinity_table_t *table, uint64_t now_ms)
{
    const uint32_t                 current_epoch = ip4_reass_tmr_epoch();
    device_frag_quarantine_sweep_t quarantine_sweep;

    /* One pass both releases safe records and inventories every free slot. The
     * inventory is consumed monotonically below, so mixed recovery is linear in
     * the quarantine and association table sizes. */
    deviceFragQuarantineSweep(table, now_ms, &quarantine_sweep);

    for (uint32_t i = 0; i < (uint32_t) kDeviceFragAffinityMaxEntries; ++i)
    {
        device_frag_affinity_entry_t *entry = &table->entries[i];
        if (entry->in_use && now_ms >= entry->expires_at_ms)
        {
            if (entry->pending_publications != 0)
            {
                /* Queue admission is not consumer delivery. */
                deviceFragAffinityPoison(table, entry);
                entry->expires_at_ms = UINT64_MAX;
            }
            else if (entry->poisoned || (entry->residue_known && entry->residue_present))
            {
                if (entry->residue_barrier_armed &&
                    deviceFragResidueBarrierReady(
                        now_ms, entry->residue_release_at_ms, current_epoch, entry->residue_release_epoch))
                {
                    deviceFragAffinityReleaseEntry(table, entry);
                    continue;
                }

                /* The last factual observation still found this exact key in
                 * lwIP. Keep only its identity for one further stack lifetime;
                 * device-side byte coverage and elapsed wall time are not proof
                 * that the reassembly timer actually ran. */
                if (! entry->residue_barrier_armed)
                {
                    deviceFragAffinityArmResidueBarrier(entry, now_ms);
                }
                const uint64_t release_at_ms = entry->residue_release_at_ms;
                const uint32_t release_epoch = entry->residue_release_epoch;
                const bool     admitted      = deviceFragQuarantineAdmitSwept(table, entry, &quarantine_sweep);

                deviceFragAffinityPoison(table, entry);
                if (admitted)
                {
                    deviceFragAffinityReleaseEntry(table, entry);
                }
                else
                {
                    entry->residue_barrier_armed = true;
                    entry->residue_release_at_ms = release_at_ms;
                    entry->residue_release_epoch = release_epoch;
                    entry->expires_at_ms         = now_ms > UINT64_MAX - (uint64_t) IP_TMR_INTERVAL
                                                       ? UINT64_MAX
                                                       : now_ms + (uint64_t) IP_TMR_INTERVAL;
                }
            }
            else
            {
                deviceFragAffinityReleaseEntry(table, entry);
            }
        }
    }
    deviceFragAffinityRefreshNextExpiry(table);
}

static device_frag_affinity_entry_t *deviceFragAffinityFind(device_frag_affinity_table_t *table,
                                                            const device_frag_view_t     *view)
{
    const uint32_t home = deviceFragAffinityHome(view);

    for (uint32_t step = 0; step < (uint32_t) kDeviceFragAffinityMaxEntries; ++step)
    {
        device_frag_affinity_entry_t *entry = &table->entries[(home + step) % kDeviceFragAffinityMaxEntries];
        if (deviceFragAffinityEntryMatches(entry, view))
        {
            return entry;
        }
    }
    return NULL;
}

static device_frag_affinity_entry_t *deviceFragAffinityInsert(device_frag_affinity_table_t *table,
                                                              const device_frag_view_t *view, uint64_t now_ms)
{
    const uint32_t home = deviceFragAffinityHome(view);

    for (uint32_t step = 0; step < (uint32_t) kDeviceFragAffinityMaxEntries; ++step)
    {
        device_frag_affinity_entry_t *entry = &table->entries[(home + step) % kDeviceFragAffinityMaxEntries];
        if (entry->in_use)
        {
            continue;
        }

        ++table->next_serial;
        if (UNLIKELY(table->next_serial == 0))
        {
            ++table->next_serial;
        }

        *entry = (device_frag_affinity_entry_t) {
            .src           = view->src,
            .dst           = view->dst,
            .ident         = view->ident,
            .proto         = view->proto,
            .serial        = table->next_serial,
            .in_use        = true,
            .expires_at_ms = now_ms + (uint64_t) kDeviceFragAffinityTimeoutMs,
        };
        table->next_expiry_ms = min(table->next_expiry_ms, entry->expires_at_ms);
        return entry;
    }
    return NULL;
}

device_frag_affinity_table_t *deviceFragAffinityCreate(buffer_pool_t *release_pool)
{
    if (release_pool == NULL)
    {
        return NULL;
    }

    device_frag_affinity_table_t *table = memoryAllocateZero(sizeof(*table));
    if (table != NULL)
    {
        table->release_pool = release_pool;
        /* Creation is the first generation; End closes it and Begin reopens it. */
        table->generation_open = true;
        table->next_expiry_ms  = UINT64_MAX;
        if (UNLIKELY(! mutexTryInit(&table->lock)))
        {
            memoryFree(table);
            return NULL;
        }
    }
    return table;
}

static void deviceFragAffinityResetLocked(device_frag_affinity_table_t *table)
{
    for (uint32_t i = 0; i < (uint32_t) kDeviceFragAffinityMaxEntries; ++i)
    {
        if (table->entries[i].in_use)
        {
            deviceFragAffinityReleaseEntry(table, &table->entries[i]);
        }
    }
    memorySet(table->quarantine, 0, sizeof(table->quarantine));
    table->quarantine_count = 0;

    table->next_expiry_ms = UINT64_MAX;
    assert(table->staged_total == 0);
    assert(table->staged_bytes == 0);
}

void deviceFragAffinityReleaseStagedBuffers(device_frag_affinity_table_t *table)
{
    if (table == NULL)
    {
        return;
    }

    mutexLock(&table->lock);
    if (table->release_pool != NULL)
    {
        for (uint32_t i = 0; i < (uint32_t) kDeviceFragAffinityMaxEntries; ++i)
        {
            if (table->entries[i].in_use)
            {
                deviceFragAffinityDropStaged(table, &table->entries[i]);
            }
        }
    }
    assert(table->staged_total == 0);
    assert(table->staged_bytes == 0);
    mutexUnlock(&table->lock);
}

void deviceFragAffinityBeginGeneration(device_frag_affinity_table_t *table)
{
    if (table == NULL)
    {
        return;
    }

    mutexLock(&table->lock);
    table->generation_open = true;
    mutexUnlock(&table->lock);
}

void deviceFragAffinityEndGeneration(device_frag_affinity_table_t *table)
{
    if (table == NULL)
    {
        return;
    }

    const uint64_t now_ms = (uint64_t) (getHRTimeUs() / 1000ULL);

    mutexLock(&table->lock);

    /*
     * Closing first is what makes the rest of this a sweep rather than a race:
     * an offer already inside the table holds this lock and finishes, and every
     * offer after it is refused outright.
     */
    table->generation_open = false;

    for (uint32_t i = 0; i < (uint32_t) kDeviceFragAffinityMaxEntries; ++i)
    {
        device_frag_affinity_entry_t *entry = &table->entries[i];
        if (! entry->in_use)
        {
            continue;
        }

        /*
         * Metadata only. The staged buffers stay where they are because the
         * reader thread still owns the pool they came from; the next
         * generation's sweep or deviceFragAffinityRetireReleasePool() returns
         * them, both from a thread that owns that pool.
         */
        deviceFragAffinityPoisonMetadata(entry);
        entry->expires_at_ms =
            entry->pending_publications != 0 ? UINT64_MAX : now_ms + (uint64_t) kDeviceFragAffinityResidueTimeoutMs;
        if (entry->pending_publications == 0)
        {
            deviceFragAffinityArmResidueBarrier(entry, now_ms);
        }
    }
    deviceFragAffinityRefreshNextExpiry(table);
    mutexUnlock(&table->lock);
}

void deviceFragAffinityRetireReleasePool(device_frag_affinity_table_t *table)
{
    if (table == NULL)
    {
        return;
    }

    assert(table->release_pool != NULL);
    mutexLock(&table->lock);
    table->generation_open = false;
    /* Outstanding receipts keep their association metadata and the session
     * alive, but staged reader buffers cannot outlive the device-owned pool. */
    for (uint32_t i = 0; i < (uint32_t) kDeviceFragAffinityMaxEntries; ++i)
    {
        if (table->entries[i].in_use)
        {
            deviceFragAffinityDropStaged(table, &table->entries[i]);
        }
    }
    assert(table->staged_total == 0);
    assert(table->staged_bytes == 0);
    table->release_pool = NULL;
    mutexUnlock(&table->lock);
}

void deviceFragAffinityDestroy(device_frag_affinity_table_t *table)
{
    if (table == NULL)
    {
        return;
    }

    mutexLock(&table->lock);
    if (table->release_pool != NULL)
    {
        deviceFragAffinityResetLocked(table);
    }
    else
    {
        /* Receipt references keep this table alive. At final destruction no
         * receipt remains, so metadata can be forgotten without pool access. */
        assert(table->staged_total == 0);
        assert(table->staged_bytes == 0);
        memoryZero(table->entries, sizeof(table->entries));
        memoryZero(table->quarantine, sizeof(table->quarantine));
        table->quarantine_count = 0;
    }
    mutexUnlock(&table->lock);
    mutexDestroy(&table->lock);
    memoryFree(table);
}

bool deviceFragAffinityPublicationMayEnter(device_frag_affinity_table_t             *table,
                                           const device_frag_affinity_publication_t *publication)
{
    if (table == NULL || publication == NULL || ! publication->valid ||
        publication->slot >= (uint16_t) kDeviceFragAffinityMaxEntries)
    {
        return false;
    }

    mutexLock(&table->lock);
    const device_frag_affinity_entry_t *entry = &table->entries[publication->slot];
    const bool allowed = table->generation_open && entry->in_use && entry->serial == publication->serial &&
                         ! entry->poisoned && entry->pending_publications != 0;
    mutexUnlock(&table->lock);
    return allowed;
}

static bool deviceFragAffinityHashAsWhole(uint8_t *packet, uint32_t length, uint64_t *out_hash, wid_t *out_wid)
{
    const uint16_t saved = GET_BE16(packet + 6);

    PUT_BE16(packet + 6, 0);
    const bool ok = deviceFlowAffinityHash(packet, length, out_hash);
    PUT_BE16(packet + 6, saved);
    if (ok)
    {
        *out_wid = (wid_t) (*out_hash % getWorkersCount());
    }
    return ok;
}

static void deviceFragAffinityTakeStaged(device_frag_affinity_table_t *table, device_frag_affinity_entry_t *entry,
                                         device_frag_affinity_result_t *out)
{
    for (uint8_t i = 0; i < entry->staged_count; ++i)
    {
        table->release_scratch[i] = entry->staged[i].buf;
        table->staged_bytes -= sbufGetLength(entry->staged[i].buf);
        entry->staged[i] = (device_staged_frag_t) {0};
    }

    out->released       = table->release_scratch;
    out->released_count = entry->staged_count;
    table->staged_total -= entry->staged_count;
    entry->staged_count = 0;
}

/* Rejects overlap exactly as the reassembler does; adjacency is merged. */
typedef enum device_frag_account_result_e
{
    kDeviceFragAccountOk,
    kDeviceFragAccountOverlap,
    kDeviceFragAccountConflict,
    kDeviceFragAccountCapacity
} device_frag_account_result_t;

static device_frag_account_result_t deviceFragAffinityAddRange(device_frag_affinity_entry_t *entry, uint32_t begin,
                                                               uint32_t end)
{
    uint8_t insert = 0;
    while (insert < entry->range_count && entry->ranges[insert].end <= begin)
    {
        ++insert;
    }

    if (insert < entry->range_count && entry->ranges[insert].begin < end && entry->ranges[insert].end > begin)
    {
        return kDeviceFragAccountOverlap;
    }

    uint32_t merged_begin = begin;
    uint32_t merged_end   = end;
    uint8_t  erase_begin  = insert;
    uint8_t  erase_end    = insert;

    if (insert > 0 && entry->ranges[insert - 1].end == begin)
    {
        erase_begin  = (uint8_t) (insert - 1);
        merged_begin = entry->ranges[insert - 1].begin;
    }
    if (insert < entry->range_count && entry->ranges[insert].begin == end)
    {
        erase_end  = (uint8_t) (insert + 1);
        merged_end = entry->ranges[insert].end;
    }

    if (erase_begin == erase_end)
    {
        if (entry->range_count >= (uint8_t) kDeviceFragAffinityMaxRanges)
        {
            return kDeviceFragAccountCapacity;
        }
        memoryMove(&entry->ranges[insert + 1],
                   &entry->ranges[insert],
                   (size_t) (entry->range_count - insert) * sizeof(entry->ranges[0]));
        ++entry->range_count;
    }
    else
    {
        const uint8_t erased = (uint8_t) (erase_end - erase_begin);
        memoryMove(&entry->ranges[erase_begin + 1],
                   &entry->ranges[erase_end],
                   (size_t) (entry->range_count - erase_end) * sizeof(entry->ranges[0]));
        entry->range_count = (uint8_t) (entry->range_count - erased + 1);
        insert             = erase_begin;
    }

    entry->ranges[insert] = (device_frag_range_t) {.begin = merged_begin, .end = merged_end};
    return kDeviceFragAccountOk;
}

static bool deviceFragAffinityIsComplete(const device_frag_affinity_entry_t *entry)
{
    return entry->saw_last && entry->range_count == 1 && entry->ranges[0].begin == 0 &&
           entry->ranges[0].end == entry->final_end;
}

static device_frag_account_result_t deviceFragAffinityAccount(device_frag_affinity_entry_t *entry,
                                                              const device_frag_view_t     *view)
{
    const uint32_t end = (uint32_t) view->offset + view->payload_len;

    if (! view->more_fragments)
    {
        if (entry->saw_last && entry->final_end != end)
        {
            return kDeviceFragAccountConflict;
        }
        if (! entry->saw_last && entry->range_count != 0 && entry->ranges[entry->range_count - 1].end > end)
        {
            return kDeviceFragAccountConflict;
        }
    }
    else if (entry->saw_last && end > entry->final_end)
    {
        return kDeviceFragAccountConflict;
    }

    const device_frag_account_result_t range_result = deviceFragAffinityAddRange(entry, view->offset, end);
    if (range_result != kDeviceFragAccountOk)
    {
        return range_result;
    }

    if (! view->more_fragments)
    {
        entry->saw_last  = true;
        entry->final_end = end;
    }
    return kDeviceFragAccountOk;
}

static device_frag_affinity_action_t deviceFragAffinityDropCurrent(device_frag_affinity_table_t *table, sbuf_t *buf)
{
    assert(table->release_pool != NULL);
    bufferpoolReuseBuffer(table->release_pool, buf);
    return kDeviceFragAffinityConsumedDrop;
}

/*
 * Finds or creates the association this fragment belongs to, or answers NULL
 * when the fragment must simply be consumed.
 *
 * NULL covers everything that has to refuse before any coverage is accounted: a
 * closed producer generation, an identity still quarantined because its
 * reassembly residue is unknown, an exhausted table, a malformed fragment, an
 * already-poisoned identity, and one arriving behind a completion that has not
 * settled yet.
 */
static device_frag_affinity_entry_t *deviceFragAffinityAdmitLocked(device_frag_affinity_table_t *table,
                                                                   const device_frag_view_t     *view,
                                                                   device_frag_parse_result_t parsed, uint64_t now_ms)
{
    if (! table->generation_open)
    {
        /*
         * A tail with no fragment zero produces no dispatch at all, so it would
         * otherwise never reach the reader session's own admission check and
         * would survive into the next generation as a healthy adoptable entry.
         */
        return NULL;
    }

    if (now_ms >= table->next_expiry_ms)
    {
        deviceFragAffinitySweep(table, now_ms);
    }

    device_frag_affinity_entry_t *entry = deviceFragAffinityFind(table, view);

    if (entry == NULL)
    {
        /*
         * A quarantined identity was released while reassembly might still hold
         * a prefix of it. Re-adopting it is exactly how an accepted prefix and a
         * later same-identification datagram combine into a hybrid.
         */
        if (deviceFragQuarantineBlocks(table, view, now_ms))
        {
            return NULL;
        }

        entry = deviceFragAffinityInsert(table, view, now_ms);
        if (entry == NULL)
        {
            if (atomicLogRateLimiterShouldLog(&g_frag_affinity_full_log, kDeviceFragAffinityLogIntervalMs))
            {
                LOGD("device fragment affinity: association capacity exhausted; dropping one datagram");
            }
            return NULL;
        }
    }

    if (entry->poisoned)
    {
        /* A rejected retry is not a new residue observation. Preserve the
         * original wall/epoch barrier instead of restarting it forever. */
        return NULL;
    }

    if (parsed == kDeviceFragParseInvalid || UNLIKELY(entry->completion_pending))
    {
        deviceFragAffinityPoison(table, entry);
        return NULL;
    }

    return entry;
}

static device_frag_affinity_action_t deviceFragAffinityOfferAtLocked(device_frag_affinity_table_t *table,
                                                                     uint64_t now_ms, const uint8_t *packet,
                                                                     uint32_t length, sbuf_t *buf,
                                                                     device_frag_affinity_result_t *out)
{
    if (out != NULL)
    {
        *out = (device_frag_affinity_result_t) {0};
    }

    device_frag_view_t               view   = {0};
    const device_frag_parse_result_t parsed = deviceFragAffinityParse(packet, length, &view);

    if (parsed == kDeviceFragParseNotFragment)
    {
        return kDeviceFragAffinityNotFragment;
    }
    assert(table != NULL);
    assert(table->release_pool != NULL);
    assert(buf != NULL);
    assert(out != NULL);

    device_frag_affinity_entry_t *entry = deviceFragAffinityAdmitLocked(table, &view, parsed, now_ms);
    if (entry == NULL)
    {
        return deviceFragAffinityDropCurrent(table, buf);
    }

    const bool is_zero        = view.offset == 0;
    uint64_t   zero_flow_hash = 0;
    wid_t      zero_hashed    = 0;
    if (is_zero)
    {
        if (! deviceFragAffinityHashAsWhole(sbufGetMutablePtr(buf), length, &zero_flow_hash, &zero_hashed))
        {
            deviceFragAffinityPoison(table, entry);
            return deviceFragAffinityDropCurrent(table, buf);
        }

        if (entry->wid_known && entry->zero_flow_hash != zero_flow_hash)
        {
            deviceFragAffinityPoison(table, entry);
            return deviceFragAffinityDropCurrent(table, buf);
        }
    }

    const device_frag_account_result_t account_result = deviceFragAffinityAccount(entry, &view);
    if (account_result != kDeviceFragAccountOk)
    {
        /*
         * A rejected fragment never changes coverage. An overlapping zero must
         * also reclaim any staged tails because it cannot safely publish them.
         */
        if ((is_zero && entry->staged_count != 0) || account_result == kDeviceFragAccountConflict ||
            account_result == kDeviceFragAccountCapacity)
        {
            deviceFragAffinityPoison(table, entry);
        }
        return deviceFragAffinityDropCurrent(table, buf);
    }

    if (is_zero && ! entry->wid_known)
    {
        entry->wid_known      = true;
        entry->wid            = zero_hashed;
        entry->zero_flow_hash = zero_flow_hash;
        entry->expires_at_ms  = now_ms + (uint64_t) kDeviceFragAffinityTimeoutMs;
        deviceFragAffinityRefreshNextExpiry(table);
        deviceFragAffinityTakeStaged(table, entry, out);
    }

    if (! entry->wid_known)
    {
        const uint32_t bytes = sbufGetLength(buf);
        if (entry->staged_count >= (uint8_t) kDeviceFragAffinityMaxStagedPerEntry ||
            table->staged_total >= (uint32_t) kDeviceFragAffinityMaxStaged ||
            bytes > (uint32_t) kDeviceFragAffinityMaxStagedBytes - table->staged_bytes)
        {
            deviceFragAffinityPoison(table, entry);
            return deviceFragAffinityDropCurrent(table, buf);
        }

        entry->staged[entry->staged_count++] = (device_staged_frag_t) {
            .buf            = buf,
            .offset         = view.offset,
            .payload_len    = view.payload_len,
            .more_fragments = view.more_fragments,
        };
        ++table->staged_total;
        table->staged_bytes += bytes;
        assert(out->released_count == 0);
        return kDeviceFragAffinityStaged;
    }

    const bool completes_datagram = deviceFragAffinityIsComplete(entry);
    out->wid                      = entry->wid;
    out->publication              = (device_frag_affinity_publication_t) {
                     .serial = entry->serial,
                     .slot   = (uint16_t) (entry - table->entries),
                     .count  = (uint16_t) (out->released_count + 1U),
                     .valid  = true,
    };
    entry->pending_publications += out->publication.count;
    entry->completion_pending = completes_datagram;
    return kDeviceFragAffinityDispatch;
}

/*
 * Retires an identity whose residue is unknown.
 *
 * The association slot is handed back and only the identity is retained, so a
 * burst of ordinary refusals cannot occupy the association table for a whole
 * reassembly lifetime. When every quarantine record is still live the poisoned
 * association stays where it is: a live quarantine is never evicted to admit
 * another identity.
 */
static void deviceFragAffinityQuarantineEntry(device_frag_affinity_table_t *table, device_frag_affinity_entry_t *entry,
                                              uint64_t now_ms)
{
    if (deviceFragQuarantineAdmit(table, entry, now_ms))
    {
        deviceFragAffinityReleaseEntry(table, entry);
        return;
    }

    if (! entry->residue_barrier_armed)
    {
        deviceFragAffinityArmResidueBarrier(entry, now_ms);
    }
    entry->expires_at_ms = entry->residue_release_at_ms;
}

/*
 * Applies one settled publication's outcome to the identity's terminal state.
 * Called only once every token of this identity has settled.
 */
static void deviceFragAffinitySettleTerminalLocked(device_frag_affinity_table_t *table,
                                                   device_frag_affinity_entry_t *entry, uint64_t now_ms)
{
    if (entry->poisoned)
    {
        deviceFragAffinityQuarantineEntry(table, entry, now_ms);
        return;
    }

    /*
     * Releasing means the identity becomes adoptable again immediately, so it
     * needs one of two proofs: the datagram completed, or the consumer purged
     * the exact reassembly key and nothing of it remains.
     */
    if (entry->residue_known && ! entry->residue_present)
    {
        deviceFragAffinityReleaseEntry(table, entry);
        return;
    }

    /*
     * A healthy but incomplete association. Its lifetime restarts from real
     * settlement rather than from the read that admitted fragment zero: a
     * fragment can sit in a paused worker queue for most of the reader-side
     * timeout, and lwIP only starts its own reassembly lifetime when the worker
     * finally consumes it. Never shortened, so publications settling out of
     * order cannot pull a later deadline back.
     */
    const uint64_t settled_deadline = now_ms + (uint64_t) kDeviceFragAffinityTimeoutMs;
    if (settled_deadline > entry->expires_at_ms)
    {
        entry->expires_at_ms = settled_deadline;
    }
}

static void deviceFragAffinitySettlePublicationAt(device_frag_affinity_table_t *table, uint64_t now_ms,
                                                  const device_frag_affinity_publication_t *publication,
                                                  device_frag_settlement_t                  settlement)
{
    if (table == NULL || publication == NULL || ! publication->valid ||
        publication->slot >= (uint16_t) kDeviceFragAffinityMaxEntries)
    {
        return;
    }

    mutexLock(&table->lock);
    device_frag_affinity_entry_t *entry = &table->entries[publication->slot];
    if (! entry->in_use || entry->serial != publication->serial)
    {
        mutexUnlock(&table->lock);
        return;
    }

    assert(entry->pending_publications >= publication->count);
    if (UNLIKELY(entry->pending_publications < publication->count))
    {
        deviceFragAffinityPoison(table, entry);
        deviceFragAffinityArmResidueBarrier(entry, now_ms);
        entry->expires_at_ms = entry->residue_release_at_ms;
        deviceFragAffinityRefreshNextExpiry(table);
        mutexUnlock(&table->lock);
        return;
    }
    entry->pending_publications -= publication->count;

    switch (settlement)
    {
    case kDeviceFragSettlementUnknown:
        /* Poisoned until expiry so a delivered prefix cannot mix with a retry. */
        deviceFragAffinityPoison(table, entry);
        break;

    case kDeviceFragSettlementNoResidue:
        entry->completion_pending = false;
        entry->residue_known      = true;
        entry->residue_present    = false;
        break;

    case kDeviceFragSettlementResiduePresent:
        entry->residue_known   = true;
        entry->residue_present = true;
        deviceFragAffinityArmResidueBarrier(entry, now_ms);
        break;
    }

    if (entry->pending_publications == 0)
    {
        deviceFragAffinitySettleTerminalLocked(table, entry, now_ms);
    }
    else if (entry->poisoned)
    {
        /* Pending work still names this slot; it cannot be reused or quarantined yet. */
        entry->expires_at_ms = UINT64_MAX;
    }

    deviceFragAffinityRefreshNextExpiry(table);
    mutexUnlock(&table->lock);
}

void deviceFragAffinitySettlePublication(device_frag_affinity_table_t             *table,
                                         const device_frag_affinity_publication_t *publication,
                                         device_frag_settlement_t                  settlement)
{
    deviceFragAffinitySettlePublicationAt(table, (uint64_t) (getHRTimeUs() / 1000ULL), publication, settlement);
}

device_frag_affinity_action_t deviceFragAffinityOffer(device_frag_affinity_table_t *table, const uint8_t *packet,
                                                      uint32_t length, sbuf_t *buf, device_frag_affinity_result_t *out)
{
    const uint64_t now_ms = (uint64_t) (getHRTimeUs() / 1000ULL);
    if (table == NULL)
    {
        return deviceFragAffinityOfferAtLocked(table, now_ms, packet, length, buf, out);
    }

    mutexLock(&table->lock);
    const device_frag_affinity_action_t action =
        deviceFragAffinityOfferAtLocked(table, now_ms, packet, length, buf, out);
    mutexUnlock(&table->lock);
    return action;
}
