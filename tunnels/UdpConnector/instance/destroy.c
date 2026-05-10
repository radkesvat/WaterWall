#include "structure.h"

#include "loggers/network_logger.h"

void udpconnectorTunnelDestroy(tunnel_t *t)
{
    udpconnector_tstate_t *ts = tunnelGetState(t);

    idletableDestroy(ts->idle_table);

    if (ts->destinations != NULL)
    {
        for (uint32_t i = 0; i < ts->destinations_count; ++i)
        {
            udpconnectorDestinationDeinit(&ts->destinations[i]);
        }
        memoryFree(ts->destinations);
    }

    dynamicvalueDestroy(ts->dest_addr_selected);
    dynamicvalueDestroy(ts->dest_port_selected);

    tunnelDestroy(t);
}
