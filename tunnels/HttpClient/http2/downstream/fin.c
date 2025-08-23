#include "structure.h"

#include "loggers/network_logger.h"

void httpclientTunnelDownStreamFinish(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamFinish(t, l);
}
