#include "structure.h"

#include "loggers/network_logger.h"

api_result_t tcpoverudpclientTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    (void) instance;
    // Implement the API here
    return tunnelapiRecycleMessage(message);
}
