#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelDestroy(tunnel_t *t)
{
    usercontroller_tstate_t *ts = tunnelGetState(t);
    usercontrollerTunnelstateDestroy(ts);
    tunnelDestroy(t);
}
