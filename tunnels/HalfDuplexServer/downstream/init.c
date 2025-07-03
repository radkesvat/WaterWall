#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;

    LOGF("HalfDuplexServer is not supposed to receive downstream init");
    terminateProgram(1);
}
