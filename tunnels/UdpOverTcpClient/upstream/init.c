#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientTunnelUpStreamInit(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamInit(t, l);
}
