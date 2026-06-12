#include "structure.h"

#include "loggers/network_logger.h"

void authenticationclientTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("AuthenticationClient: UpStreamEst is disabled");
    terminateProgram(1);
}
