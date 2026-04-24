#include "structure.h"

#include "loggers/network_logger.h"

void connectionfisherclientTunnelDestroy(tunnel_t *t)
{
    tunnelDestroy(t);
}
