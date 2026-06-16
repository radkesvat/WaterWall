#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamEst(t, l);
}
