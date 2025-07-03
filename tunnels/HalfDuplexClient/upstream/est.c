#include "structure.h"

#include "loggers/network_logger.h"

void halfduplexclientTunnelUpStreamEst(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;

    LOGF("HalfDuplexClient will not receive a upstream est");
    terminateProgram(1);    
}
