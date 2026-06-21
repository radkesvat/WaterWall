#include "structure.h"

#include "loggers/network_logger.h"

void junkdatagramsenderTunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamPause(t, l);
}
