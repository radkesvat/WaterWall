#include "structure.h"

#include "loggers/network_logger.h"

void obfuscatorclientTunnelDownStreamResume(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamResume(t, l);
}
