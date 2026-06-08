#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelDestroy(tunnel_t *t)
{
    tcpconnector_tstate_t *ts = tunnelGetState(t);

    if (ts->idle_table != NULL)
    {
        idletableDestroy(ts->idle_table);
    }

    if (ts->probe_timer != NULL)
    {
        weventSetUserData(ts->probe_timer, NULL);
        wtimerDelete(ts->probe_timer);
        ts->probe_timer = NULL;
    }
    tcpconnectorCancelActiveProbes(t);

    if (ts->probe_mutex_initialized)
    {
        mutexDestroy(&ts->probe_mutex);
        ts->probe_mutex_initialized = false;
    }

    if (ts->destinations != NULL)
    {
        for (uint32_t i = 0; i < ts->destinations_count; ++i)
        {
            tcpconnectorDestinationDeinit(&ts->destinations[i]);
        }
        memoryFree(ts->destinations);
    }

    memoryFree(ts->destination_stats);

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
