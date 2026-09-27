#include "devices/device_flow_affinity.h"

#include "devices/device_frag_affinity.h"
#include "global_state.h"

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

static wid_t deviceFlowAffinitySelectWID(const sbuf_t *buf)
{
    wid_t target_wid;

    if (deviceFlowAffineWID(sbufGetRawPtr(buf), sbufGetLength(buf), &target_wid))
    {
        return target_wid;
    }

    return getNextDistributionWID();
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
        dispatch[filled]              = buf;
        dispatch_wids[filled]         = (uint8_t) deviceFlowAffinitySelectWID(buf);
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
                                         DeviceReaderPrepareFn prepare)
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
            const uint16_t     chunk = min(remaining, session->batch_capacity);
            const unsigned int first = (unsigned int) offsets[wid] + posted;
            bool               accepted;
            if (charges == NULL)
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

void deviceFlowAffinityPostBatch(device_reader_session_t *session, sbuf_t **bufs, unsigned int count)
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

        const bool admitted = deviceFlowAffinityPostSorted(session, dispatch, wids, NULL, dispatch_count, NULL);

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

void deviceFlowAffinityPostGsoBatch(device_reader_session_t *session, sbuf_t **bufs, const size_t *charges,
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
            wids[i] = (uint8_t) deviceFlowAffinitySelectWID(bufs[i]);
        }

        if (! deviceFlowAffinityPostSorted(session, bufs, wids, charges, chunk_count, prepare))
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
