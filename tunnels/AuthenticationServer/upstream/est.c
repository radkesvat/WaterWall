#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("AuthenticationServer: UpStreamEst is disabled");
    terminateProgram(1);
}
