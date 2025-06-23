#include "structure.h"

#include "loggers/network_logger.h"

api_result_t ipoverriderApi(tunnel_t *instance, sbuf_t *message)
{
    (void)instance;
    bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), message);
    // Implement the API here
    return (api_result_t){.result_code = kApiResultOk};
}
