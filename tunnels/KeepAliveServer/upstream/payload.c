#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveserverTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    keepaliveserver_lstate_t *ls = lineGetState(l, t);

    switch (spliceframereaderAdmit(&ls->reader, buf))
    {
    case kSpliceFrameDrain:
        keepaliveserverConsumeUpstreamFrames(t, l);
        return;
    case kSpliceFrameQueued:
    case kSpliceFrameEmpty:
        return;
    case kSpliceFrameByteLimit:
    case kSpliceFrameChargeLimit:
    case kSpliceFramePushFailed:
        keepaliveserverCloseLineFromProtocolError(t, l);
        return;
    }
}
