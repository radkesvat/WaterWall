#include "internal.h"

#include "loggers/network_logger.h"

api_result_t vmessclientTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    (void) instance;
    return tunnelapiRecycleMessage(message);
}
