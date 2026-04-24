#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherserverTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    discard t;
    discard l;
    LOGF("ConnectionFisherServer: downstream init disabled");
    terminateProgram(1);
}
