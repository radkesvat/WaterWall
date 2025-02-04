#include "structure.h"

#include "loggers/network_logger.h"

void templateTunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamPause(t, l);
}
