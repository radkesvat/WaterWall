#include "structure.h"

#include "loggers/network_logger.h"

void reverseclientTunnelOnStart(tunnel_t *t)
{
    int wc = getWorkersCount() - WORKER_ADDITIONS;

    for (int i = 0; i < wc; i++)
    {
        reverseclientInitiateConnectOnWorker(t, i, true);
    }
}
