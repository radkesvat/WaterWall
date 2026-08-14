#include "structure.h"

#include "loggers/network_logger.h"

api_result_t ctpTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    // Implement the API here
    return tunnelapiRecycleMessage(message);
}
