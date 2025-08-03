#include "structure.h"

#include "loggers/network_logger.h"

void tcpoverudpclientTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamPause(t, l);
}
