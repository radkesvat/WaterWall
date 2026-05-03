#include "structure.h"

#include "loggers/network_logger.h"

api_result_t loggertunnelTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;

    if (message != NULL)
    {
        bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), message);
    }

    return (api_result_t) {.result_code = kApiResultOk};
}
