#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelOnIndex(tunnel_t *t, tunnel_array_t *arr, uint16_t *index, uint16_t *mem_offset)
{
    // using tunnel / adapter default handle for this action
    (void) t;
    (void) arr;
    (void) index;
    (void) mem_offset;
    LOGF("This Function is disabled, using the default Tunnel instead");
    exit(1);
}
