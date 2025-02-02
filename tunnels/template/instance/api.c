#include "structure.h"

api_result_t templateTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    (void)instance;
    bufferpoolResuesBuffer(getWorkerBufferPool(getWID()), message);
    // Implement the API here
    return (api_result_t){.result_code = kApiResultOk};
}
