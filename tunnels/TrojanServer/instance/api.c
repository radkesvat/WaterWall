#include "structure.h"

api_result_t trojanserverTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    return tunnelapiRecycleMessage(message);
}
