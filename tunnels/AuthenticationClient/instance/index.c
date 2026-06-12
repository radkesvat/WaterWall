#include "structure.h"

#include "loggers/network_logger.h"

void authenticationclientTunnelOnIndex(tunnel_t *t, uint16_t index, uint16_t *mem_offset)
{
    tunnelDefaultOnIndex(t, index, mem_offset);
}
