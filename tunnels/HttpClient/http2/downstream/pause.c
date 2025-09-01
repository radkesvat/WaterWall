#include "structure.h"

#include "loggers/network_logger.h"

void httpclientV2TunnelDownStreamPause(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamPause(t, l);
}
