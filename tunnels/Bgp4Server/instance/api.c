#include "structure.h"

#include "loggers/network_logger.h"

api_result_t bgp4serverTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    return tunnelapiRecycleMessage(message);
}
