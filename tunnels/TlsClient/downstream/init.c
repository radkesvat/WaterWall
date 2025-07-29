#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{

    discard t;
    discard l;
    LOGF("TlsClient: downstream init is disabled");
    terminateProgram(1);
}
