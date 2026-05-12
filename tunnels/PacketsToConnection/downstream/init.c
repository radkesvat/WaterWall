#include "structure.h"

#include "loggers/network_logger.h"

void ptcTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("Impossible call");
    terminateProgram(1);
}
