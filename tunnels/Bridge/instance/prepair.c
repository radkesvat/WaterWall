#include "structure.h"

#include "loggers/network_logger.h"

void bridgeTunnelOnPrepair(tunnel_t *t)
{
    // using tunnel / adapter default handle for this action
    discard t;

    LOGF("This Function is disabled, using the default Tunnel instead");
    terminateProgram(1);

}
