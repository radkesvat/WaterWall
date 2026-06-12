#include "structure.h"

#include "loggers/network_logger.h"

api_result_t authenticationclientTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    discard message;

    return (api_result_t) {.result_code = kApiResultError, .buffer = NULL};
}
