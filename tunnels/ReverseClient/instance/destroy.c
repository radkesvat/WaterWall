#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelDestroy(tunnel_t *t)
{
    reverseclient_tstate_t *ts = tunnelGetState(t);

    idleTableDestroy(ts->starved_connections);
    tunnelDestroy(t);
}
