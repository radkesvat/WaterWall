#include "structure.h"

#include "loggers/network_logger.h"

void vlessserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("VlessServer: UpStreamEst is disabled");
    terminateProgram(1);
}
