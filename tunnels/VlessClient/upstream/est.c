#include "structure.h"

#include "loggers/network_logger.h"

void vlessclientTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("VlessClient: UpStreamEst is disabled");
    terminateProgram(1);
}
