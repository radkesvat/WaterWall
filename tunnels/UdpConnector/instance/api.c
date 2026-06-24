#include "structure.h"

#include "UdpConnector/interface.h"

#include "loggers/network_logger.h"

api_result_t udpconnectorTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    (void) instance;
    bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), message);
    // Implement the API here
    return (api_result_t) {.result_code = kApiResultOk};
}

tunnel_t *udpconnectorTunnelGetEntryTunnel(tunnel_t *t)
{
    udpconnector_tstate_t *ts = tunnelGetState(t);
    return ts->domain_setup_tunnel != NULL ? ts->domain_setup_tunnel : t;
}
