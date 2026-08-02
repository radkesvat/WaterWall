#include "structure.h"

#include "loggers/network_logger.h"

api_result_t udplistenerTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    (void) instance;
    // Implement the API here
    return tunnelapiRecycleMessage(message);
}
