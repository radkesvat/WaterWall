#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelDestroy(tunnel_t *t)
{
    tcpconnector_tstate_t *ts = tunnelGetState(t);

    if (ts->idle_tables != NULL)
    {
        for (wid_t wid = 0; wid < getWorkersCount(); ++wid)
        {
            if (ts->idle_tables[wid] != NULL)
            {
                LOGW("TcpConnector: destroying with active worker-local idle table for worker %u", (unsigned int) wid);
            }
        }
        memoryFree(ts->idle_tables);
        ts->idle_tables = NULL;
    }

    if (ts->destinations != NULL)
    {
        for (uint32_t i = 0; i < ts->destinations_count; ++i)
        {
            tcpconnectorDestinationDeinit(&ts->destinations[i]);
        }
        memoryFree(ts->destinations);
    }

    dynamicvalueDestroy(ts->dest_addr_selected);
    dynamicvalueDestroy(ts->dest_port_selected);
    if (ts->interface_name != NULL)
    {
        memoryFree(ts->interface_name);
    }
    if (ts->source_ip != NULL)
    {
        memoryFree(ts->source_ip);
    }

    tunnelDestroy(t);
}
