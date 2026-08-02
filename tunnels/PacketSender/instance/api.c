#include "structure.h"

#include "loggers/network_logger.h"

api_result_t packetsenderTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    return tunnelapiRecycleMessage(message);
}
