#include "structure.h"

#include "loggers/network_logger.h"

void usercontrollerTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamEst(t, l);
}
