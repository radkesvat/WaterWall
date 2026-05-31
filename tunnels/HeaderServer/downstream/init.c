#include "structure.h"

#include "loggers/network_logger.h"

void headerserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("HeaderServer: DownStreamInit is disabled");
    terminateProgram(1);
}
