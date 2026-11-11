#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveclientTunnelDownStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    keepaliveclient_lstate_t *ls = lineGetState(l, t);

    const size_t incoming_bytes = sbufGetLength(buf);
    const size_t retained_bytes = spliceframereaderLength(&ls->reader);
    switch (spliceframereaderAdmit(&ls->reader, buf))
    {
    case kSpliceFrameDrain:
        keepaliveclientConsumeDownstreamFrames(t, l);
        return;
    case kSpliceFrameQueued:
    case kSpliceFrameEmpty:
        return;
    case kSpliceFrameByteLimit:
        LOGW("KeepAliveClient: closing connection: nested input byte limit exceeded "
             "(retained_bytes=%zu, incoming_bytes=%zu, limit_bytes=%u)",
             retained_bytes,
             incoming_bytes,
             (unsigned) kKeepAliveMaxReentryBytes);
        keepaliveclientCloseLineFromProtocolError(t, l);
        return;
    case kSpliceFrameChargeLimit:
        LOGW("KeepAliveClient: closing connection: nested input storage charge exceeded "
             "(retained_charge_bytes=%zu, limit_charge_bytes=%u)",
             spliceframereaderCharge(&ls->reader),
             (unsigned) kKeepAliveReadChargeLimit);
        keepaliveclientCloseLineFromProtocolError(t, l);
        return;
    case kSpliceFramePushFailed:
        LOGW("KeepAliveClient: closing connection: input queue admission failed "
             "(retained_bytes=%zu, incoming_bytes=%zu)",
             retained_bytes,
             incoming_bytes);
        keepaliveclientCloseLineFromProtocolError(t, l);
        return;
    }
}
