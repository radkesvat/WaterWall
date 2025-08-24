#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelOnStart(tunnel_t *t)
{
    int wc = getWorkersCount();

    for (int i = 0; i < wc; i++)
    {
        reverseclientInitiateConnectOnWorker(t, i, true);
    }
}
