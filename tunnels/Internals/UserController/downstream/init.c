#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    // A downstream-initiated line (reverse chains) has no authenticated user to enforce; we still
    // initialize our per-line state so later callbacks find it, then forward untouched.
    usercontrollerLinestateInitialize(lineGetState(l, t));
    tunnelPrevDownStreamInit(t, l);
}
