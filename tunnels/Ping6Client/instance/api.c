#include "structure.h"

#include "loggers/network_logger.h"

api_result_t ping6clientApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    return tunnelapiRecycleMessage(message);
}
