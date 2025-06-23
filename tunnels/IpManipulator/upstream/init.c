#include "structure.h"

#include "loggers/network_logger.h"

void ipmanipulatorUpStreamInit(tunnel_t *t, line_t *l)
{
    tunnelNextUpStreamInit(t, l);
}
