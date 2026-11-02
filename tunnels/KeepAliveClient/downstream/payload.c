#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    keepaliveclient_lstate_t *ls = lineGetState(l, t);

    switch (spliceframereaderAdmit(&ls->reader, buf))
    {
    case kSpliceFrameDrain:
        keepaliveclientConsumeDownstreamFrames(t, l);
        return;
    case kSpliceFrameQueued:
    case kSpliceFrameEmpty:
        return;
    case kSpliceFrameByteLimit:
    case kSpliceFrameChargeLimit:
    case kSpliceFramePushFailed:
        keepaliveclientCloseLineFromProtocolError(t, l);
        return;
    }
}
