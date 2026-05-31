#include "structure.h"

#include "loggers/network_logger.h"

void bgp4serverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("Bgp4Server: DownStreamInit is disabled");
    terminateProgram(1);
}
