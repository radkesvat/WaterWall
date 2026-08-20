#include "structure.h"

#include "loggers/network_logger.h"

void testerserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("TesterServer: upStreamEst disabled");
    abortProgramNow(1);
}
