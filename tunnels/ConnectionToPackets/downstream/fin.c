#include "structure.h"

#include "loggers/network_logger.h"

void ctpTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    /*
     * Only the chain's persistent packet lines are ever handed to next, and a
     * packet line cannot be closed: this node anchors the packet lifecycle here,
     * so a close is a contract violation rather than a flow event. Destroying the
     * packet line would be strictly worse than failing loudly.
     */
    LOGF("ConnectionToPackets: unexpected downstream Finish on the packet line");
    abortProgramNow(1);
}
