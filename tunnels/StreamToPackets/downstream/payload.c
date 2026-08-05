#include "structure.h"

#include "loggers/network_logger.h"

// Kept in its own block below the logger: device_flow_affinity.h pulls in the
// internal logger, and whichever logger a translation unit sees first is the
// one every LOGx in it reports to.
#include "devices/device_flow_affinity.h"

/*
 * One return packet arriving from the packet chain on worker packet line @p l.
 *
 * The return carrier is chosen per inner flow by rendezvous hashing over the
 * active, unpaused stream lines of the current source generation, so it need not
 * be the line the forward packet arrived on. While that pool is unchanged, the
 * symmetric flow hash keeps one flow on one line.
 */
void streamtopacketsTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    uint64_t flow_hash = 0;

    if (sbufGetLength(buf) > kMaxAllowedPacketLength)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    streamtopacketsRecalculateChecksumIfRequested(l, buf);

    // The wire format is a raw concatenation of IPv4 packets; the peer recovers boundaries
    // from each packet's IPv4 total-length field. Drop anything that is not a self-consistent
    // IPv4 packet (this also drops IPv6) so we never feed the peer unframable bytes.
    if (UNLIKELY(! streamtopacketsIsForwardableIpv4Packet(buf)))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    if (UNLIKELY(! deviceFlowAffinityHash(sbufGetRawPtr(buf), sbufGetLength(buf), &flow_hash)))
    {
        LOGW("StreamToPackets: dropping a return packet whose inner flow could not be hashed");
        lineReuseBuffer(l, buf);
        return;
    }

    streamtopackets_selected_line_t selected;

    if (! streamtopacketsSelectReturnLine(t, flow_hash, &selected))
    {
        // No active, unpaused line of the current source: candidates, paused,
        // stale-generation and foreign-source lines are never used as a fallback.
        lineReuseBuffer(l, buf);
        return;
    }

    if (lineIsOnCurrentEventWorker(selected.line))
    {
        // The same validated delivery routine as the queued path: being on the
        // right worker is not a reason to skip a check.
        streamtopacketsDeliverSelectedWrite(t, selected.line, selected.line_id, selected.generation, buf);
        lineUnlock(selected.line);
        return;
    }

    streamtopacketsQueueSelectedWrite(t, &selected, buf);
}
