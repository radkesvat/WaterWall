#include "structure.h"

#include "UdpConnector/interface.h"

#include "loggers/network_logger.h"

api_result_t udpconnectorTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    (void) instance;
    // Implement the API here
    return tunnelapiRecycleMessage(message);
}

tunnel_t *udpconnectorTunnelGetEntryTunnel(tunnel_t *t)
{
    udpconnector_tstate_t *ts = tunnelGetState(t);
    return ts->domain_resolver_tunnel != NULL ? ts->domain_resolver_tunnel : t;
}

void udpconnectorTunnelSetDnsProvider(tunnel_t *t, tunnel_t *provider)
{
    udpconnector_tstate_t *ts = tunnelGetState(t);
    domainresolverTunnelSetProvider(ts->domain_resolver_tunnel, provider);
}
