#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("PacketsToConnection: unexpected upstream Resume on the packet line");
    terminateProgram(1);
}
