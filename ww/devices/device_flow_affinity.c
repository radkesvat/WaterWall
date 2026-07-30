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

static wid_t deviceFlowAffinityHash(uint32_t src, uint16_t src_port, uint32_t dst, uint16_t dst_port, uint8_t proto,
                                    uint32_t fragment_key)
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
    hash = deviceFlowAffinityMix64(hash);

    return (wid_t) (hash % getWorkersCount());
}

static uint32_t deviceFlowAffinityFoldIpv6Address(const uint8_t *address)
{
    return GET_BE32(address) ^ GET_BE32(address + 4) ^ GET_BE32(address + 8) ^ GET_BE32(address + 12);
}

bool deviceFlowAffineWID(const uint8_t *packet, uint32_t length, wid_t *out_wid)
{
    if (packet == NULL || out_wid == NULL)
    {
        return false;
    }

    if (getWorkersCount() <= 1)
    {
        *out_wid = 0;
        return true;
    }

    uint8_t  version      = length > 0 ? packet[0] >> 4U : 0;
    uint8_t  proto        = 0;
    uint32_t src          = 0;
    uint32_t dst          = 0;
    uint32_t fragment_key = 0;
    uint16_t src_port     = 0;
    uint16_t dst_port     = 0;

    if (version == 4)
    {
        if (length < 20)
        {
            return false;
        }

        uint32_t ip_header_len = (uint32_t) (packet[0] & 0x0FU) * 4U;
        if (ip_header_len < 20 || ip_header_len > 60 || length < ip_header_len)
        {
            return false;
        }

        proto = packet[9];
        src   = GET_BE32(packet + 12);
        dst   = GET_BE32(packet + 16);

        uint16_t fragment_field = GET_BE16(packet + 6);
        bool     fragmented =
            (fragment_field & (kDeviceFlowAffinityIpv4MoreFragments | kDeviceFlowAffinityIpv4OffsetMask)) != 0;
        if (fragmented)
        {
            /*
             * Every fragment of one datagram must reach the same worker. The
             * leading fragment has transport bytes but later fragments do not,
             * so use the IP identification for all of them.
             */
            fragment_key = UINT32_C(0x10000) | GET_BE16(packet + 4);
        }
        else if ((proto == 6 || proto == 17 || proto == 132) && length >= ip_header_len + 4U)
        {
            src_port = GET_BE16(packet + ip_header_len);
            dst_port = GET_BE16(packet + ip_header_len + 2U);
        }
    }
    else if (version == 6)
    {
        if (length < 40)
        {
            return false;
        }

        proto = packet[6];
        src   = deviceFlowAffinityFoldIpv6Address(packet + 8);
        dst   = deviceFlowAffinityFoldIpv6Address(packet + 24);

        if ((proto == 6 || proto == 17) && length >= 44)
        {
            src_port = GET_BE16(packet + 40);
            dst_port = GET_BE16(packet + 42);
        }
    }
    else
    {
        return false;
    }

    *out_wid = deviceFlowAffinityHash(src, src_port, dst, dst_port, proto, fragment_key);
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
