#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("AuthenticationServer: DownStreamInit is disabled");
    terminateProgram(1);
}
