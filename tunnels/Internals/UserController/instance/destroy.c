#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard                  context;
    usercontroller_tstate_t *ts = tunnelGetState(t);
    usercontrollerTunnelstateDestroy(ts);
    tunnelDestroy(t);
}
