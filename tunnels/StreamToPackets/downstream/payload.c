#include "structure.h"

#include "loggers/network_logger.h"

void streamtopacketsTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    line_t                   *packet_line = tunnelchainGetWorkerPacketLine(tunnelGetChain(t), lineGetWID(l));
    streamtopackets_lstate_t *ls          = lineGetState(packet_line, t);

    if (ls->paused || ls->line == NULL || ! lineIsAlive(ls->line) || sbufGetLength(buf) > kMaxAllowedPacketLength)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    streamtopacketsRecalculateChecksumIfRequested(l, buf);

    // The wire format is now a raw concatenation of IPv4 packets; the peer recovers boundaries
    // from each packet's IPv4 total-length field. Drop anything that is not a self-consistent
    // IPv4 packet (this also drops IPv6) so we never feed the peer unframable bytes.
    if (UNLIKELY(! streamtopacketsIsForwardableIpv4Packet(buf)))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    tunnelPrevDownStreamPayload(t, ls->line, buf);
}
