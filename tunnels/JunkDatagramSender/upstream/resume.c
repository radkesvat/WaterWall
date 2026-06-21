#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderTunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamResume(t, l);
}
