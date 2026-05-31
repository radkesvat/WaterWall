#include "structure.h"

#include "loggers/network_logger.h"

void bgp4clientTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("Bgp4Client: UpStreamEst is disabled");
    terminateProgram(1);
}
