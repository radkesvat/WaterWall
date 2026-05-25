#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveclientTunnelUpStreamPayload(tunnel_t *t, line_t *l, sbuf_t *buf)
{
    discard keepaliveclientSendNormalFrameUpstream(t, l, buf);
}
