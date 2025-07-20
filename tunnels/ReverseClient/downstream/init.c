#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{

    discard t;
    discard l;
    LOGF("ReverseClient: DownStreamInit is disabled, this should not be called");
    terminateProgram(1);
}
