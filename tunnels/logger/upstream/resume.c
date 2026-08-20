#include "structure.h"

#include "loggers/network_logger.h"

void loggertunnelTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamResume(t, l);
}
