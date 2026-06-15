#include "structure.h"

api_result_t tcpudpconnectorTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    bufferpoolReuseBuffer(getWorkerBufferPool(getWID()), message);
    return (api_result_t) {.result_code = kApiResultOk};
}
