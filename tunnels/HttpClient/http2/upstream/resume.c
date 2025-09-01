#include "structure.h"

#include "loggers/network_logger.h"

void httpclientV2TunnelUpStreamResume(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamResume(t, l);
}
