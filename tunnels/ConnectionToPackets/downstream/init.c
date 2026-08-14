#include "structure.h"

#include "loggers/network_logger.h"

void ctpTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    // Nothing downstream of this node opens a line toward it: normal lines come
    // from prev and the packet lines are initialized by onStart().
    LOGF("ConnectionToPackets: unexpected downstream Init");
    abortProgramNow(1);
}
