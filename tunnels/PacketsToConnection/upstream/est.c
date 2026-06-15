#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("PacketsToConnection: unexpected upstream Est on the packet line");
    terminateProgram(1);
}
