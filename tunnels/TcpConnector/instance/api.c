#include "structure.h"

#include "TcpConnector/interface.h"

#include "loggers/network_logger.h"

api_result_t tcpconnectorTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    (void) instance;
    bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), message);
    // Implement the API here
    return (api_result_t) {.result_code = kApiResultOk};
}

tunnel_t *tcpconnectorTunnelGetEntryTunnel(tunnel_t *t)
{
    tcpconnector_tstate_t *ts = tunnelGetState(t);
    return ts->domain_setup_tunnel != NULL ? ts->domain_setup_tunnel : t;
}
