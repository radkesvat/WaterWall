#include "structure.h"

#include "loggers/network_logger.h"

void headerclientTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}
