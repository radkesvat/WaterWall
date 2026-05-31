#include "structure.h"

#include "loggers/network_logger.h"

void bgp4clientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("Bgp4Client: DownStreamInit is disabled");
    terminateProgram(1);
}
