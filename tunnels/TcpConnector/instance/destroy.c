#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelDestroy(tunnel_t *t)
{
    tcpconnector_tstate_t *ts = tunnelGetState(t);
    
    idletableDestroy(ts->idle_table);

    dynamicvalueDestroy(ts->dest_addr_selected);
    dynamicvalueDestroy(ts->dest_port_selected);

    tunnelDestroy(t);
}
