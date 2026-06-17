#include "structure.h"

#include "loggers/network_logger.h"

void trojanserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TrojanServer: UpStreamEst is disabled");
    terminateProgram(1);
}
