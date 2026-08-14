#include "structure.h"

#include "loggers/network_logger.h"

void ctpTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    /*
     * Only a packet line can reach this node from next, and establishment has no
     * meaning for one: it is a persistent chain object, not a flow. Some packet
     * nodes still emit it after their own startup, so it is absorbed rather than
     * treated as a violation.
     */
}
