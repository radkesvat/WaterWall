#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelDownStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("AuthenticationServer: DownStreamEst is disabled");
    terminateProgram(1);
}
