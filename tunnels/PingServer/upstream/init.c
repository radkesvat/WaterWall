#include "structure.h"

#include "loggers/network_logger.h"

void pingserverUpStreamInit(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamInit(t, l);
}
