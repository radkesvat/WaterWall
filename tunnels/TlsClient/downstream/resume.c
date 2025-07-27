#include "structure.h"

#include "loggers/network_logger.h"

void tlsclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamResume(t, l);
}
