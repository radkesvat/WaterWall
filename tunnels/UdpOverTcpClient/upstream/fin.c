#include "structure.h"

#include "loggers/network_logger.h"

void udpovertcpclientTunnelUpStreamFinish(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamFinish(t, l);
}
