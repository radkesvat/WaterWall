#include "structure.h"

#include "loggers/network_logger.h"

void packetstostreamTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    packetstostream_lstate_t *ls = lineGetState(l, t);
    line_t                   *stream_line;

    stream_line = packetstostreamEnsureOutputLine(t, l, ls);

    if (stream_line == NULL || ls->paused || sbufGetLength(buf) > kMaxAllowedPacketLength)
    {
        lineReuseBuffer(l, buf);
        return;
    }

    packetstostreamRecalculateChecksumIfRequested(l, buf);

    // The wire format is now a raw concatenation of IPv4 packets; the peer recovers boundaries
    // from each packet's IPv4 total-length field. Drop anything that is not a self-consistent
    // IPv4 packet (this also drops IPv6) so we never feed the peer unframable bytes.
    if (UNLIKELY(! packetstostreamIsForwardableIpv4Packet(buf)))
    {
        lineReuseBuffer(l, buf);
        return;
    }

    tunnelNextUpStreamPayload(t, stream_line, buf);
}
