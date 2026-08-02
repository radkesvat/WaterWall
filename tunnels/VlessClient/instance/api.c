#include "structure.h"

#include "loggers/network_logger.h"

api_result_t vlessclientTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    (void) instance;
    return tunnelapiRecycleMessage(message);
}
