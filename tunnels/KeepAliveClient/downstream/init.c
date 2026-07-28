#include "structure.h"

#include "loggers/network_logger.h"

void keepaliveclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("KeepAliveClient: DownStreamInit is disabled");
    abortProgramNow(1);
}
