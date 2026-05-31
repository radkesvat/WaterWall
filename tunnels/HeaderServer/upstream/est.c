#include "structure.h"

#include "loggers/network_logger.h"

void headerserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("HeaderServer: UpStreamEst is disabled");
    terminateProgram(1);
}
