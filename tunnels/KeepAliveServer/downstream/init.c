#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("KeepAliveServer: DownStreamInit is disabled");
    abortProgramNow(1);
}
