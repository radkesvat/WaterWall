#include "structure.h"

#include "loggers/network_logger.h"

void tcplistenerTunnelDestroy(tunnel_t *t, const ww_lifecycle_context_t *context)
{
    discard               context;
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

    memoryFree(tstate->listen_address);

    tunnelDestroy(t);
}
