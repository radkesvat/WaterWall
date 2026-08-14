#include "structure.h"

#include "loggers/network_logger.h"

void ctpTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    // The matching Pause was never applied to any flow, so there is nothing to
    // release here either.
    LOGD("ConnectionToPackets: ignoring Resume on the packet line, it is not per-flow backpressure");
}
