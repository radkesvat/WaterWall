#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("ReverseClient: UpStream Init is disabled");
    terminateProgram(1);
}
