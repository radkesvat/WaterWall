#include "structure.h"

#include "loggers/network_logger.h"

void packetstostreamTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    packetstostream_lstate_t *ls = lineGetState(l, t);
    line_t                   *stream_line;
    bool                      created;

    stream_line = packetstostreamEnsureOutputLine(t, l, ls, &created);

    if (stream_line == NULL || ls->paused || sbufGetLength(buf) > kMaxAllowedPacketLength)
    {
        lineReuseBuffer(l, buf);
        if (created)
        {
            packetstostreamResumePacketSource(t, l, ls, stream_line);
        }
        return;
    }

    packetstostreamRecalculateChecksumIfRequested(l, buf);

    // The wire format is now a raw concatenation of IPv4 packets; the peer recovers boundaries
    // from each packet's IPv4 total-length field. Drop anything that is not a self-consistent
    // IPv4 packet (this also drops IPv6) so we never feed the peer unframable bytes.
    if (UNLIKELY(! packetstostreamIsForwardableIpv4Packet(buf)))
    {
        lineReuseBuffer(l, buf);
        if (created)
        {
            packetstostreamResumePacketSource(t, l, ls, stream_line);
        }
        return;
    }

    if (! created)
    {
        tunnelNextUpStreamPayload(t, stream_line, buf);
        return;
    }

    // Resume can synchronously release newer packets; hand off this one first.
    if (lineCallWithRefWithBuf(stream_line, tunnelNextUpStreamPayload, t, buf))
    {
        packetstostreamResumePacketSource(t, l, ls, stream_line);
    }
}
