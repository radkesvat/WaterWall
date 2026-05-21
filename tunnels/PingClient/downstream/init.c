#include "structure.h"

#include "loggers/network_logger.h"

void pingclientDownStreamInit(tunnel_t *t, line_t *l)
{
    tunnelPrevDownStreamInit(t, l);
}
