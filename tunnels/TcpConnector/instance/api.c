#include "structure.h"

#include "TcpConnector/interface.h"

#include "loggers/network_logger.h"

api_result_t tcpconnectorTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    (void) instance;
    // Implement the API here
    return tunnelapiRecycleMessage(message);
}

tunnel_t *tcpconnectorTunnelGetEntryTunnel(tunnel_t *t)
{
    tcpconnector_tstate_t *ts = tunnelGetState(t);
    return ts->domain_resolver_tunnel != NULL ? ts->domain_resolver_tunnel : t;
}
