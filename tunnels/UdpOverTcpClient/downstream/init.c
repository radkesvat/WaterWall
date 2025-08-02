#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientTunnelDownStreamInit(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamInit(t, l);
}
