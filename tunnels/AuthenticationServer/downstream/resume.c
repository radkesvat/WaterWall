#include "structure.h"

#include "loggers/network_logger.h"

void authenticationserverTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("AuthenticationServer: DownStreamResume is disabled");
    terminateProgram(1);
}
