#include "structure.h"

#include "loggers/network_logger.h"

void httpclientV2TunnelUpStreamPause(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamPause(t, l);
}
