#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset)
{
    // using tunnel / adapter default handle for this action
    discard t;

    discard index;
    discard mem_offset;
    LOGF("This Function is disabled, using the default Tunnel instead");
    terminateProgram(1);
}
