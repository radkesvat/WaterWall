#include "devices/device_frag_affinity.h"
#include "devices/device_flow_affinity.h"
#include "global_state.h"
#include "loggers/internal_logger.h"
#include "lwip/inet_chksum.h"
#include "lwip/prot/tcp.h"
#include "lwip/prot/udp.h"
#include "wchecksum.h"

enum
{
    kDeviceFragAffinityIpv4MoreFragments = 0x2000,
    kDeviceFragAffinityIpv4OffsetMask    = 0x1fff,
    kDeviceFragAffinityMaxPayloadEnd     = UINT16_MAX - 20U
};
typedef struct device_frag_range_s
{
    uint32_t begin, end;
} device_frag_range_t;
typedef struct device_frag_affinity_entry_s
{
    uint32_t            src, dst;
    uint16_t            ident;
    uint8_t             proto;
    bool                in_use, poisoned, wid_known, saw_last;
    wid_t               wid;
    uint64_t            expires_at_ms;
    uint64_t zero_flow_hash;
    uint32_t            final_end;
    uint16_t            fragments;
    uint8_t             range_count, staged_count;
    device_frag_range_t ranges[kDeviceFragAffinityMaxRanges];
    sbuf_t             *staged[kDeviceFragAffinityMaxStagedPerEntry];
    sbuf_t             *assembly;
} device_frag_affinity_entry_t;
struct device_frag_affinity_table_s
{
    buffer_pool_t               *release_pool;
    wmutex_t                     lock;
    bool                         generation_open;
    device_fragment_policy_t     policy;
    size_t                       retained_bytes;
    uint32_t                     staged_total;
    sbuf_t                      *release_scratch[kDeviceFragAffinityMaxStagedPerEntry];
    device_frag_affinity_entry_t entries[kDeviceFragAffinityMaxEntries];
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

static void deviceFragReleaseStorage(device_frag_affinity_table_t *table, device_frag_affinity_entry_t *entry)
{
    for (unsigned i = 0; i < entry->staged_count; ++i)
    {
        table->retained_bytes -= sbufGetAllocationCharge(entry->staged[i]);
        bufferpoolReuseBuffer(table->release_pool, entry->staged[i]);
    }
    table->staged_total -= entry->staged_count;
    entry->staged_count = 0;
    if (entry->assembly)
    {
        table->retained_bytes -= sbufGetAllocationCharge(entry->assembly);
        bufferpoolReuseBuffer(table->release_pool, entry->assembly);
        entry->assembly = NULL;
    }
}
static void deviceFragPoison(device_frag_affinity_table_t *table, device_frag_affinity_entry_t *entry, uint64_t now)
{
    deviceFragReleaseStorage(table, entry);
    if (! entry->poisoned)
    {
        entry->poisoned      = true;
        entry->expires_at_ms = now + kDeviceFragAffinityTimeoutMs;
    }
}
static void deviceFragSweep(device_frag_affinity_table_t *table, uint64_t now)
{
    for (unsigned i = 0; i < kDeviceFragAffinityMaxEntries; ++i)
    {
        device_frag_affinity_entry_t *entry = &table->entries[i];
        if (! entry->in_use || now < entry->expires_at_ms)
            continue;
        if (entry->poisoned)
        {
            deviceFragReleaseStorage(table, entry);
            *entry = (device_frag_affinity_entry_t) {0};
        }
        else
        {
            /* Expired payload gets one fixed local poison interval. No stack receipt. */
            uint64_t expiry = entry->expires_at_ms;
            deviceFragPoison(table, entry, expiry);
            if (now >= entry->expires_at_ms)
                *entry = (device_frag_affinity_entry_t) {0};
        }
    }
}
device_frag_affinity_table_t *deviceFragAffinityCreate(buffer_pool_t *pool, device_fragment_policy_t policy)
{
    if (policy != kDeviceFragmentReassemble && policy != kDeviceFragmentPreserve)
        return NULL;
    if (! pool)
        return NULL;
    device_frag_affinity_table_t *table = memoryAllocateZero(sizeof(*table));
    if (! table)
        return NULL;
    if (! mutexTryInit(&table->lock))
    {
        memoryFree(table);
        return NULL;
    }
    table->release_pool    = pool;
    table->policy          = policy;
    table->generation_open = true;
    return table;
}
void deviceFragAffinityBeginGeneration(device_frag_affinity_table_t *table)
{
    if (! table)
        return;
    mutexLock(&table->lock);
    table->generation_open = true;
    mutexUnlock(&table->lock);
}
void deviceFragAffinityEndGeneration(device_frag_affinity_table_t *table)
{
    if (! table)
        return;
    uint64_t now = getHRTimeUs() / 1000ULL;
    mutexLock(&table->lock);
    table->generation_open = false;
    for (unsigned i = 0; i < kDeviceFragAffinityMaxEntries; ++i)
    {
        device_frag_affinity_entry_t *entry = &table->entries[i];
        /* Lifecycle thread never accesses the reader's pool. */
        if (entry->in_use && ! entry->poisoned)
        {
            entry->poisoned      = true;
            entry->expires_at_ms = now + kDeviceFragAffinityTimeoutMs;
        }
    }
    mutexUnlock(&table->lock);
}
void deviceFragAffinityReleaseStagedBuffers(device_frag_affinity_table_t *table)
{
    if (! table)
        return;
    mutexLock(&table->lock);
    for (unsigned i = 0; i < kDeviceFragAffinityMaxEntries; ++i)
        deviceFragReleaseStorage(table, &table->entries[i]);
    assert(table->retained_bytes == 0 && table->staged_total == 0);
    mutexUnlock(&table->lock);
}
void deviceFragAffinityRetireReleasePool(device_frag_affinity_table_t *table)
{
    if (! table)
        return;
    deviceFragAffinityReleaseStagedBuffers(table);
    mutexLock(&table->lock);
    table->generation_open = false;
    table->release_pool    = NULL;
    mutexUnlock(&table->lock);
}
void deviceFragAffinityDestroy(device_frag_affinity_table_t *table)
{
    if (! table)
        return;
    deviceFragAffinityReleaseStagedBuffers(table);
    mutexDestroy(&table->lock);
    memoryFree(table);
}

/* Caller holds the mutex and owns the reader pool. Rejections consume input. */
static device_frag_affinity_action_t deviceFragOfferLocked(device_frag_affinity_table_t *table,
                                                           const device_frag_view_t     *view,
                                                           device_frag_parse_result_t parsed, sbuf_t *buf,
                                                           device_frag_affinity_result_t *out, uint64_t now)
{
    device_frag_affinity_entry_t *entry = NULL, *free_entry = NULL;
    if (! table->generation_open)
        goto drop;
    deviceFragSweep(table, now);
    for (unsigned i = 0; i < kDeviceFragAffinityMaxEntries; ++i)
    {
        device_frag_affinity_entry_t *candidate = &table->entries[i];
        if (! candidate->in_use)
        {
            if (! free_entry)
                free_entry = candidate;
            continue;
        }
        if (candidate->src == view->src && candidate->dst == view->dst && candidate->ident == view->ident &&
            candidate->proto == view->proto)
        {
            entry = candidate;
            break;
        }
    }
    if (! entry)
    {
        if (! free_entry)
            goto drop;
        entry  = free_entry;
        *entry = (device_frag_affinity_entry_t) {.src           = view->src,
                                                 .dst           = view->dst,
                                                 .ident         = view->ident,
                                                 .proto         = view->proto,
                                                 .in_use        = true,
                                                 .expires_at_ms = now + kDeviceFragAffinityTimeoutMs};
    }
    if (entry->poisoned)
        goto drop;
    if (parsed == kDeviceFragParseInvalid || entry->fragments == kDeviceFragAffinityMaxFragments)
        goto poison;
    uint64_t zero_hash = 0;
    wid_t    zero_wid  = 0;
    if (table->policy == kDeviceFragmentPreserve && view->offset == 0)
    {
        if (! deviceFragAffinityHashAsWhole(sbufGetMutablePtr(buf), sbufGetLength(buf), &zero_hash, &zero_wid) ||
            (entry->wid_known && entry->zero_flow_hash != zero_hash))
            goto poison;
    }
    /* Account into a candidate so allocation refusal never publishes unwritten coverage. */
    device_frag_affinity_entry_t candidate = *entry;
    device_frag_account_result_t accounted = deviceFragAffinityAccount(&candidate, view);
    if (accounted != kDeviceFragAccountOk)
    {
        if (accounted != kDeviceFragAccountOverlap || (view->offset == 0 && ! entry->wid_known))
            goto poison;
        goto drop;
    }
    if (table->policy == kDeviceFragmentReassemble)
    {
        const uint32_t need    = 20U + (uint32_t) view->offset + view->payload_len;
        const uint16_t padding = bufferpoolGetLargeBufferPadding(table->release_pool);
        if (! entry->assembly || need > sbufGetMaximumWriteableSize(entry->assembly))
        {
            buffer_pool_fit_t fit;
            if (! bufferpoolQueryBestFit(table->release_pool, need, padding, &fit) ||
                fit.allocation_charge > kDeviceFragAffinityMaxAssemblyBytes - table->retained_bytes)
                goto poison;
            /* Reserve the full replacement, including the still-live old allocation. */
            table->retained_bytes += fit.allocation_charge;
            sbuf_t *grown = bufferpoolTryGetBestFit(table->release_pool, need, padding);
            if (UNLIKELY(grown == NULL || sbufGetAllocationCharge(grown) != fit.allocation_charge ||
                         sbufGetMaximumWriteableSize(grown) < need || sbufGetLeftCapacity(grown) < padding))
            {
                LOGF("Device fragment assembly: best-fit allocation geometry changed");
                abortProgramNow(1);
            }
            if (entry->assembly)
            {
                if (entry->wid_known)
                    memoryCopy(sbufGetMutablePtr(grown), sbufGetRawPtr(entry->assembly), 20);
                for (unsigned i = 0; i < entry->range_count; ++i)
                {
                    device_frag_range_t r = entry->ranges[i];
                    memoryCopy(sbufGetMutablePtr(grown) + 20 + r.begin,
                               (const uint8_t *) sbufGetRawPtr(entry->assembly) + 20 + r.begin,
                               r.end - r.begin);
                }
                table->retained_bytes -= sbufGetAllocationCharge(entry->assembly);
                bufferpoolReuseBuffer(table->release_pool, entry->assembly);
            }
            candidate.assembly = grown;
        }
        uint8_t *bytes = sbufGetMutablePtr(candidate.assembly);
        if (view->offset == 0)
        {
            memoryCopy(bytes, sbufGetRawPtr(buf), 20);
            candidate.wid_known = true;
        }
        memoryCopy(bytes + 20 + view->offset, (const uint8_t *) sbufGetRawPtr(buf) + 20, view->payload_len);
        ++candidate.fragments;
        *entry = candidate;
        bufferpoolReuseBuffer(table->release_pool, buf);
        if (! entry->wid_known || ! deviceFragAffinityIsComplete(entry))
            return kDeviceFragAffinityStaged;
        /* Fragment zero is authoritative for TOS/TTL/DF/reserved bits; clear only MF/offset. */
        PUT_BE16(bytes + 2, 20U + entry->final_end);
        PUT_BE16(bytes + 6, GET_BE16(bytes + 6) & 0xc000U);
        PUT_BE16(bytes + 10, 0);
        PUT_BE16(bytes + 10, deviceIpv4HeaderChecksum(bytes, 20));
        sbufSetLength(entry->assembly, 20U + entry->final_end);
        out->completed = entry->assembly;
        table->retained_bytes -= sbufGetAllocationCharge(entry->assembly);
        *entry = (device_frag_affinity_entry_t) {0};
        return kDeviceFragAffinityComplete;
    }
    if (view->offset == 0 && ! entry->wid_known)
    {
        candidate.zero_flow_hash = zero_hash;
        candidate.wid            = zero_wid;
        candidate.wid_known      = true;
    }
    if (! candidate.wid_known)
    {
        size_t charge = sbufGetAllocationCharge(buf);
        if (candidate.staged_count == kDeviceFragAffinityMaxStagedPerEntry ||
            table->staged_total == kDeviceFragAffinityMaxStaged ||
            charge > kDeviceFragAffinityMaxStagedBytes - table->retained_bytes)
            goto poison;
        candidate.staged[candidate.staged_count++] = buf;
        ++table->staged_total;
        table->retained_bytes += charge;
        ++candidate.fragments;
        *entry = candidate;
        return kDeviceFragAffinityStaged;
    }
    out->wid            = candidate.wid;
    out->released       = table->release_scratch;
    out->released_count = candidate.staged_count;
    for (unsigned i = 0; i < candidate.staged_count; ++i)
    {
        table->release_scratch[i] = candidate.staged[i];
        table->retained_bytes -= sbufGetAllocationCharge(candidate.staged[i]);
    }
    table->staged_total -= candidate.staged_count;
    candidate.staged_count = 0;
    ++candidate.fragments;
    *entry = candidate;
    if (deviceFragAffinityIsComplete(entry))
        *entry = (device_frag_affinity_entry_t) {0};
    return kDeviceFragAffinityDispatch;
poison:
    deviceFragPoison(table, entry, now);
drop:
    bufferpoolReuseBuffer(table->release_pool, buf);
    return kDeviceFragAffinityConsumedDrop;
}

device_frag_affinity_action_t deviceFragAffinityOffer(device_frag_affinity_table_t *table, const uint8_t *packet,
                                                      uint32_t length, sbuf_t *buf, device_frag_affinity_result_t *out)
{
    *out                              = (device_frag_affinity_result_t) {0};
    device_frag_view_t         view   = {0};
    device_frag_parse_result_t parsed = deviceFragAffinityParse(packet, length, &view);
    if (parsed == kDeviceFragParseNotFragment)
        return kDeviceFragAffinityNotFragment;
    assert(table && table->release_pool);
    mutexLock(&table->lock);
    device_frag_affinity_action_t result =
        deviceFragOfferLocked(table, &view, parsed, buf, out, getHRTimeUs() / 1000ULL);
    mutexUnlock(&table->lock);
    return result;
}
