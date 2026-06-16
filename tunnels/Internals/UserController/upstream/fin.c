#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    // prev/downstream side finished us: release our reserved slot and propagate the finish to next.
    usercontrollerCloseLine(t, l, kUserControllerCloseFromPrev);
}
