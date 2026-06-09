#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelDestroy(tunnel_t *t)
{
    tcplistener_tstate_t *tstate = tunnelGetState(t);

    if (tstate->idle_tables)
    {
        for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
        {
            if (tstate->idle_tables[wid] != NULL)
            {
                LOGW("TcpListener: local idle table for worker %u was not stopped before destroy", (unsigned int) wid);
            }
        }
        memoryFree(tstate->idle_tables);
        tstate->idle_tables = NULL;
    }

    if (tstate->listen_address)
    {
        memoryFree(tstate->listen_address);
    }
    if (tstate->white_list_range)
    {
        memoryFree((void *) tstate->white_list_range);
    }
    if (tstate->black_list_range)
    {
        memoryFree((void *) tstate->black_list_range);
    }

    tunnelDestroy(t);
}
