#include "structure.h"

#include "loggers/network_logger.h"

void bgp4serverTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("Bgp4Server: UpStreamEst is disabled");
    terminateProgram(1);
}
