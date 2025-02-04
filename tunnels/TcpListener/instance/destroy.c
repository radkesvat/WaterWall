#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelDestroy(tunnel_t *t)
{
    tcplistener_tstate_t *tstate = tunnelGetState(t);
    if (tstate->listen_address)
    {
        memoryFree(tstate->listen_address);
    }
    if (tstate->white_list_range)
    {
        memoryFree(tstate->white_list_range);
    }
    if (tstate->black_list_range)
    {
        memoryFree(tstate->black_list_range);
    }
    memoryFree(tstate);

    tunnelDestroy(t);
}

