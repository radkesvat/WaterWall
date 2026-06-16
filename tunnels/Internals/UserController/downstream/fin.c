#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    // next/upstream side finished us: release our reserved slot and propagate the finish to prev.
    usercontrollerCloseLine(t, l, kUserControllerCloseFromNext);
}
