#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tunnelPrevdownStreamFinish(t, l);
}
