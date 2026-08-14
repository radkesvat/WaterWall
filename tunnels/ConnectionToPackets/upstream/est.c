#include "structure.h"

#include "loggers/network_logger.h"

void ctpTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    // Establishment always travels from the network side toward prev, so nothing
    // upstream of this node can be the one reporting it.
    LOGF("ConnectionToPackets: upstream Est is not supposed to be called");
    abortProgramNow(1);
}
