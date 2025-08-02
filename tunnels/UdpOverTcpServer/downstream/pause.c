#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpserverTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamPause(t, l);
}
