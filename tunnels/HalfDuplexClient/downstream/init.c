#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;

    LOGF("HalfDuplexClient will not receive a backward init");
    terminateProgram(1);    
}
