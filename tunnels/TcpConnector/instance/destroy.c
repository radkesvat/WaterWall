#include "structure.h"

#include "loggers/network_logger.h"

void tcpconnectorTunnelDestroy(tunnel_t *t)
{
    tcpconnector_tstate_t *state = tunnelGetState(t);

    dynamicvalueDestroy(state->dest_addr_selected);
    dynamicvalueDestroy(state->dest_port_selected);

    tunnelDestroy(t);
}
