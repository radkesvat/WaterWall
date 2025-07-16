#include "structure.h"

#include "loggers/network_logger.h"

void dataaspacketTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    
    discard t;
    discard l;

    LOGF("DataAsPacket: not supposed to receive init downstream, your chain is incorrectly designed");
    // we operate left to right, no reason to pass init downside
}
