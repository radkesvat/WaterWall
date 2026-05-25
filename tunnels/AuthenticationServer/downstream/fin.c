#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("AuthenticationServer: DownStreamFinish is disabled");
    terminateProgram(1);
}
