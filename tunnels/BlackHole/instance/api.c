#include "structure.h"

#include "loggers/network_logger.h"

api_result_t blackholeTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), message);
    return (api_result_t) {.result_code = kApiResultOk};
}
