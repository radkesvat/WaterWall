#include "devices/device_flow_affinity.h"

#include "global_state.h"

enum
{
    kDeviceFlowAffinityMaxBatch          = 512,
    kDeviceFlowAffinityBuckets           = UINT8_MAX + 1,
    kDeviceFlowAffinityIpv4MoreFragments = 0x2000,
    kDeviceFlowAffinityIpv4OffsetMask    = 0x1FFF
};

static uint64_t deviceFlowAffinityMix64(uint64_t value)
{
    value ^= value >> 30U;
    value *= UINT64_C(0xBF58476D1CE4E5B9);
    value ^= value >> 27U;
    value *= UINT64_C(0x94D049BB133111EB);
    value ^= value >> 31U;
    return value;
}

static uint64_t deviceFlowAffinityMixTuple(uint32_t src, uint16_t src_port, uint32_t dst, uint16_t dst_port,
                                           uint8_t proto, uint32_t fragment_key)
{
    uint64_t endpoint_a = ((uint64_t) src << 16U) | src_port;
    uint64_t endpoint_b = ((uint64_t) dst << 16U) | dst_port;
    uint64_t low        = min(endpoint_a, endpoint_b);
    uint64_t high       = max(endpoint_a, endpoint_b);
    uint64_t hash       = deviceFlowAffinityMix64(low + UINT64_C(0x9E3779B97F4A7C15));

    hash ^= deviceFlowAffinityMix64(high + UINT64_C(0xD1B54A32D192ED03));
    hash ^= deviceFlowAffinityMix64((uint64_t) proto + UINT64_C(0x94D049BB133111EB));
    if (fragment_key != 0)
    {
        hash ^= deviceFlowAffinityMix64((uint64_t) fragment_key + UINT64_C(0xDB4F0B9175AE2165));
    }

    return deviceFlowAffinityMix64(hash);
}

static uint32_t deviceFlowAffinityFoldIpv6Address(const uint8_t *address)
{
    return GET_BE32(address) ^ GET_BE32(address + 4) ^ GET_BE32(address + 8) ^ GET_BE32(address + 12);
}

// The flow-identifying fields one IP packet contributes to the hash.
typedef struct device_flow_affinity_tuple_s
{
    uint32_t src;
    uint32_t dst;
    uint32_t fragment_key;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  proto;
} device_flow_affinity_tuple_t;

static bool deviceFlowAffinityParseIpv4(const uint8_t *packet, uint32_t length, device_flow_affinity_tuple_t *out)
{
    if (length < 20)
    {
        return false;
    }

    const uint32_t ip_header_len = (uint32_t) (packet[0] & 0x0FU) * 4U;
    if (ip_header_len < 20 || ip_header_len > 60 || length < ip_header_len)
    {
        return false;
    }

    /*
     * The declared total length is what bounds this packet, not the buffer: a
     * buffer may carry trailing bytes that are not part of the datagram, and
     * reading ports out of them would hash two different flows alike. This is the
     * same structural test ipv4packetviewParse() applies.
     */
    const uint32_t ip_total_len = GET_BE16(packet + 2);
    if (ip_total_len < ip_header_len || ip_total_len > length)
    {
        return false;
    }

    out->proto = packet[9];
    out->src   = GET_BE32(packet + 12);
    out->dst   = GET_BE32(packet + 16);

    const uint16_t fragment_field = GET_BE16(packet + 6);
    if ((fragment_field & (kDeviceFlowAffinityIpv4MoreFragments | kDeviceFlowAffinityIpv4OffsetMask)) != 0)
    {
        /*
         * Every fragment of one datagram must reach the same worker. The leading
         * fragment has transport bytes but later fragments do not, so use the IP
         * identification for all of them. This affinity is scoped to the IP
         * datagram; unfragmented packets include ports and may select a different
         * worker for the surrounding transport flow.
         */
        out->fragment_key = UINT32_C(0x10000) | GET_BE16(packet + 4);
        return true;
    }

    const bool has_ports = out->proto == 6 || out->proto == 17 || out->proto == 132;
    if (has_ports && ip_total_len >= ip_header_len + 4U)
    {
        out->src_port = GET_BE16(packet + ip_header_len);
        out->dst_port = GET_BE16(packet + ip_header_len + 2U);
    }

    return true;
}

static bool deviceFlowAffinityParseIpv6(const uint8_t *packet, uint32_t length, device_flow_affinity_tuple_t *out)
{
    if (length < 40)
    {
        return false;
    }

    /*
     * A truncated payload is malformed. A zero payload length is not an empty
     * packet either: RFC 2675 makes it the marker for a jumbogram whose real
     * size lives in a Hop-by-Hop Jumbo Payload option. This parser deliberately
     * does not walk extension headers, so it cannot tell a real jumbogram from a
     * malformed header and rejects both as unsupported. Callers fall back to
     * round-robin, which is what they already do for anything unparseable.
     */
    const uint32_t payload_len = GET_BE16(packet + 4);
    if (payload_len == 0 || payload_len + 40U > length)
    {
        return false;
    }

    out->proto = packet[6];
    out->src   = deviceFlowAffinityFoldIpv6Address(packet + 8);
    out->dst   = deviceFlowAffinityFoldIpv6Address(packet + 24);

    const bool has_ports = out->proto == 6 || out->proto == 17;
    if (has_ports && payload_len >= 4U && length >= 44)
    {
        out->src_port = GET_BE16(packet + 40);
        out->dst_port = GET_BE16(packet + 42);
    }

    return true;
}

bool deviceFlowAffinityHash(const uint8_t *packet, uint32_t length, uint64_t *out_hash)
{
    if (packet == NULL || out_hash == NULL || length == 0)
    {
        return false;
    }

    /*
     * There is deliberately no single-worker shortcut here. The hash is also the
     * per-flow identity used for stream-line selection, which can have several
     * candidates even when one worker is configured, and the malformed-packet
     * contract must hold at every worker count.
     */
    device_flow_affinity_tuple_t tuple   = {0};
    const uint8_t                version = packet[0] >> 4U;
    bool                         parsed;

    if (version == 4)
    {
        parsed = deviceFlowAffinityParseIpv4(packet, length, &tuple);
    }
    else if (version == 6)
    {
        parsed = deviceFlowAffinityParseIpv6(packet, length, &tuple);
    }
    else
    {
        return false;
    }

    if (! parsed)
    {
        return false;
    }

    *out_hash = deviceFlowAffinityMixTuple(
        tuple.src, tuple.src_port, tuple.dst, tuple.dst_port, tuple.proto, tuple.fragment_key);
    return true;
}

bool deviceFlowAffineWID(const uint8_t *packet, uint32_t length, wid_t *out_wid)
{
    uint64_t hash;

    if (out_wid == NULL || ! deviceFlowAffinityHash(packet, length, &hash))
    {
        return false;
    }

    *out_wid = (wid_t) (hash % getWorkersCount());
    return true;
}

static wid_t deviceFlowAffinitySelectWID(const sbuf_t *buf)
{
    wid_t target_wid;

    if (deviceFlowAffineWID(sbufGetRawPtr(buf), sbufGetLength(buf), &target_wid))
    {
        return target_wid;
    }

    return getNextDistributionWID();
}

void deviceFlowAffinityPostBatch(device_reader_session_t *session, sbuf_t **bufs, unsigned int count)
{
    assert(session != NULL);
    assert(bufs != NULL);

    while (count > 0)
    {
        unsigned int chunk_count                         = min(count, (unsigned int) kDeviceFlowAffinityMaxBatch);
        uint16_t     counts[kDeviceFlowAffinityBuckets]  = {0};
        uint16_t     offsets[kDeviceFlowAffinityBuckets] = {0};
        uint16_t     positions[kDeviceFlowAffinityBuckets];
        uint8_t      wids[kDeviceFlowAffinityMaxBatch];
        sbuf_t      *sorted[kDeviceFlowAffinityMaxBatch];

        for (unsigned int i = 0; i < chunk_count; ++i)
        {
            wids[i] = deviceFlowAffinitySelectWID(bufs[i]);
            counts[wids[i]]++;
        }

        uint16_t offset = 0;
        for (unsigned int wid = 0; wid < kDeviceFlowAffinityBuckets; ++wid)
        {
            offsets[wid]   = offset;
            positions[wid] = offset;
            offset         = (uint16_t) (offset + counts[wid]);
        }
        assert(offset == chunk_count);

        for (unsigned int i = 0; i < chunk_count; ++i)
        {
            sorted[positions[wids[i]]++] = bufs[i];
        }

        for (unsigned int wid = 0; wid < kDeviceFlowAffinityBuckets; ++wid)
        {
            if (counts[wid] > 0)
            {
                deviceReaderSessionPost(session, (wid_t) wid, &sorted[offsets[wid]], counts[wid]);
            }
        }

        bufs += chunk_count;
        count -= chunk_count;
    }
}
