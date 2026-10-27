#include "devices/device_flow_affinity.h"

#include "devices/device_frag_affinity.h"
#include "global_state.h"
#include "ipv4_packet_view.h"

enum
{
    kDeviceFlowAffinityMaxBatch          = 512,
    kDeviceFlowAffinityBuckets           = UINT8_MAX + 1,

    /*
     * One chunk can emit more packets than it took in: a fragment zero releases
     * the tails that were waiting for it, and those may have arrived in an
     * earlier chunk. The staging cap bounds how many that can be.
     */
    kDeviceFlowAffinityMaxDispatch = kDeviceFlowAffinityMaxBatch + kDeviceFragAffinityMaxStaged
};

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

static bool deviceReaderHasVisibleTransportTuple(const device_reader_session_t *session, const sbuf_t *buf)
{
    const uint8_t *packet = sbufGetRawPtr(buf);
    const uint32_t length = sbufGetLength(buf);
    if (length == 0)
        return false;
    if ((packet[0] >> 4U) == 4)
    {
        ipv4_packet_view_t view;
        return ipv4packetviewParse(packet, length, &view) && view.ip_total_length == length && ! view.fragmented &&
               view.transport_length >= 4 && deviceFlowPortedSetContains(&session->ported, view.protocol);
    }
    /* IPv6 extension headers are opaque here; only an immediately visible
     * TCP/UDP header exposes transport ports to the existing flow hash. */
    return (packet[0] >> 4U) == 6 && length >= 44 && GET_BE16(packet + 4) >= 4 &&
           (uint32_t) GET_BE16(packet + 4) + 40U == length && (packet[6] == IPPROTO_TCP || packet[6] == IPPROTO_UDP);
}

wid_t deviceReaderSelectWID(device_reader_session_t *session, wid_t reader_wid, uint16_t reader_count,
                            const sbuf_t *buf)
{
    assert(session != NULL && buf != NULL);
    assert(reader_count > 0 && reader_count <= getWorkersCount());
    assert(reader_wid < reader_count);
    if (reader_count > 1)
        return reader_wid;

    /* Keep this receive locality even though consumers select their own flow owner.
     * Round-robin can assign ordered segments 1,2,3 to workers 0,1,0; a delayed
     * worker 1 then makes ECH-SNI see 1,3,2 and mark this flow generation passthrough.
     * Consumer affinity orders admission only: segment 2 is still in another
     * receive queue. Opaque traffic must retain the parallel rotation below.
     * Regression: testReaderSkewPreservesClientHello in the ECH-SNI unit suite. */
    if (deviceReaderHasVisibleTransportTuple(session, buf))
    {
        uint64_t   hash = 0;
        const bool identified =
            deviceFlowAffinityHashWithPorts(sbufGetRawPtr(buf), sbufGetLength(buf), &session->ported, &hash);
        assert(identified);
        discard identified;
        return (wid_t) (hash % getWorkersCount());
    }
    return (wid_t) (atomicIncExplicit(&session->distribution_next, memory_order_relaxed) % getWorkersCount());
}

/*
 * One packet's worth of dispatch, and the fragments it may have unblocked.
 *
 * The fragment table can both withhold a packet and hand back several, so this
 * appends to the pending list rather than filling one slot: `dispatch` grows by
 * zero entries for a staged tail, and by more than one for the fragment zero
 * that releases them. Everything else is the ordinary one-in, one-out case.
 */
static unsigned int deviceFlowAffinityAppend(device_reader_session_t *session, sbuf_t *buf, sbuf_t **dispatch,
                                             uint8_t *dispatch_wids, unsigned int filled)
{
    device_frag_affinity_result_t frag;

    const device_frag_affinity_action_t action =
        deviceFragAffinityOffer(session->frag_affinity, sbufGetRawPtr(buf), sbufGetLength(buf), buf, &frag);

    if (action == kDeviceFragAffinityNotFragment || action == kDeviceFragAffinityComplete)
    {
        if (action == kDeviceFragAffinityComplete)
            buf = frag.completed;
        dispatch[filled]      = buf;
        dispatch_wids[filled] = (uint8_t) deviceReaderSelectWID(session, 0, 1, buf);
        return filled + 1;
    }

    if (action == kDeviceFragAffinityConsumedDrop)
    {
        return filled;
    }

    // The tails go out ahead of the fragment zero that decided their worker,
    // which is the order they arrived in.
    for (uint8_t i = 0; i < frag.released_count; ++i)
    {
        dispatch[filled]                    = frag.released[i];
        dispatch_wids[filled]               = (uint8_t) frag.wid;
        ++filled;
    }

    if (action == kDeviceFragAffinityStaged)
    {
        // The table owns it until its fragment zero shows up, or the caps do.
        return filled;
    }

    assert(action == kDeviceFragAffinityDispatch);
    dispatch[filled]                    = buf;
    dispatch_wids[filled]               = (uint8_t) frag.wid;
    return filled + 1;
}

/*
 * Groups an already-decided dispatch list by worker and posts one batch each.
 *
 * A counting sort rather than a per-packet post: the buffers keep their relative
 * order inside every bucket, which is what a receiving worker needs from packets
 * of one flow, and each worker's queue is touched once.
 */
static bool deviceFlowAffinityPostSorted(device_reader_session_t *session, sbuf_t **dispatch, const uint8_t *wids,
                                         const size_t *charges, unsigned int dispatch_count,
                                         DeviceReaderPrepareFn prepare, bool nonblocking)
{
    uint16_t counts[kDeviceFlowAffinityBuckets]  = {0};
    uint16_t offsets[kDeviceFlowAffinityBuckets] = {0};
    uint16_t positions[kDeviceFlowAffinityBuckets];
    sbuf_t  *sorted[kDeviceFlowAffinityMaxDispatch];
    size_t   sorted_charges[kDeviceFlowAffinityMaxDispatch];

    for (unsigned int i = 0; i < dispatch_count; ++i)
    {
        counts[wids[i]]++;
    }

    uint16_t offset = 0;
    for (unsigned int wid = 0; wid < kDeviceFlowAffinityBuckets; ++wid)
    {
        offsets[wid]   = offset;
        positions[wid] = offset;
        offset         = (uint16_t) (offset + counts[wid]);
    }
    assert(offset == dispatch_count);

    for (unsigned int i = 0; i < dispatch_count; ++i)
    {
        const uint16_t position = positions[wids[i]]++;
        sorted[position]        = dispatch[i];
        if (charges != NULL)
        {
            sorted_charges[position] = charges[i];
        }
    }

    for (unsigned int wid = 0; wid < kDeviceFlowAffinityBuckets; ++wid)
    {
        uint16_t remaining = counts[wid];
        uint16_t posted    = 0;
        while (remaining > 0)
        {
            uint16_t           chunk = min(remaining, session->batch_capacity);
            const unsigned int first = (unsigned int) offsets[wid] + posted;
            bool               accepted;
            if (nonblocking)
            {
                chunk            = min(chunk, session->output_packet_limit);
                size_t   charge  = 0;
                uint16_t fitting = 0;
                while (fitting < chunk)
                {
                    const size_t next = sbufGetAllocationCharge(sorted[first + fitting]);
                    if (next > session->output_charge_limit - charge)
                        break;
                    charge += next;
                    ++fitting;
                }
                chunk = fitting;
                const device_reader_post_result_e result =
                    chunk != 0 ? deviceReaderSessionTryPost(session, (wid_t) wid, &sorted[first], chunk)
                               : kDeviceReaderPostCapacity;
                accepted = result == kDeviceReaderPostAccepted;
                if (result == kDeviceReaderPostCapacity)
                {
                    /* Capacity refusal retains the whole chunk. Include it
                     * in the unposted remainder settled below. */
                    chunk = 0;
                }
            }
            else if (charges == NULL)
            {
                accepted = deviceReaderSessionPost(session, (wid_t) wid, &sorted[first], chunk);
            }
            else
            {
                accepted = deviceReaderSessionPostReserved(
                    session, (wid_t) wid, &sorted[first], &sorted_charges[first], chunk, prepare);
            }
            if (! accepted)
            {
                /* The refused chunk was consumed by message cleanup; these were never posted. */
                const unsigned int first_unposted = (unsigned int) offsets[wid] + posted + chunk;
                for (unsigned int i = first_unposted; i < dispatch_count; ++i)
                {
                    bufferpoolReuseBuffer(session->reader_buffer_pool, sorted[i]);
                    if (charges != NULL)
                    {
                        deviceReaderSessionReleaseOutput(session, sorted_charges[i]);
                    }
                }
                return false;
            }
            posted    = (uint16_t) (posted + chunk);
            remaining = (uint16_t) (remaining - chunk);
        }
    }
    return true;
}

static void deviceReaderDistributeBatchInternal(device_reader_session_t *session, sbuf_t **bufs, unsigned int count,
                                                bool nonblocking)
{
    assert(session != NULL);
    assert(bufs != NULL);

    while (count > 0)
    {
        const unsigned int chunk_count = min(count, (unsigned int) kDeviceFlowAffinityMaxBatch);
        uint8_t            wids[kDeviceFlowAffinityMaxDispatch];
        sbuf_t            *dispatch[kDeviceFlowAffinityMaxDispatch];
        unsigned int       dispatch_count = 0;

        for (unsigned int i = 0; i < chunk_count; ++i)
        {
            dispatch_count = deviceFlowAffinityAppend(session, bufs[i], dispatch, wids, dispatch_count);
        }

        const bool admitted =
            deviceFlowAffinityPostSorted(session, dispatch, wids, NULL, dispatch_count, NULL, nonblocking);

        if (! admitted)
        {
            /* Buffers after this parsing chunk are still owned by the reader. */
            for (unsigned int i = chunk_count; i < count; ++i)
            {
                bufferpoolReuseBuffer(session->reader_buffer_pool, bufs[i]);
            }

            /* Remaining reader-owned buffers have been released. */
            return;
        }

        bufs += chunk_count;
        count -= chunk_count;
    }
}

void deviceReaderDistributeBatch(device_reader_session_t *session, sbuf_t **bufs, unsigned int count)
{
    deviceReaderDistributeBatchInternal(session, bufs, count, false);
}

void deviceReaderDistributeBatchDroppingOverflow(device_reader_session_t *session, sbuf_t **bufs, unsigned int count)
{
    assert(session != NULL && session->worker_queues != NULL && session->output_charge_limit != 0);
    deviceReaderDistributeBatchInternal(session, bufs, count, true);
}

void deviceReaderDistributeGsoBatch(device_reader_session_t *session, sbuf_t **bufs, const size_t *charges,
                                    unsigned int count, DeviceReaderPrepareFn prepare)
{
    assert(session != NULL);
    assert(bufs != NULL);
    assert(charges != NULL);

    while (count > 0)
    {
        const unsigned int chunk_count = min(count, (unsigned int) kDeviceFlowAffinityMaxBatch);
        uint8_t            wids[kDeviceFlowAffinityMaxBatch];
        for (unsigned int i = 0; i < chunk_count; ++i)
        {
            wids[i] = (uint8_t) deviceReaderSelectWID(session, 0, 1, bufs[i]);
        }

        if (! deviceFlowAffinityPostSorted(session, bufs, wids, charges, chunk_count, prepare, false))
        {
            for (unsigned int i = chunk_count; i < count; ++i)
            {
                bufferpoolReuseBuffer(session->reader_buffer_pool, bufs[i]);
                deviceReaderSessionReleaseOutput(session, charges[i]);
            }
            return;
        }

        bufs += chunk_count;
        charges += chunk_count;
        count -= chunk_count;
    }
}
