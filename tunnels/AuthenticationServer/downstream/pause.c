#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("AuthenticationServer: DownStreamPause is disabled");
    terminateProgram(1);
}
