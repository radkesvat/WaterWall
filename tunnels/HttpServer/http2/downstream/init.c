#include "structure.h"

#include "loggers/network_logger.h"

void httpserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("HttpServer(v2): DownStream Init is disabled");
    terminateProgram(1);
}
