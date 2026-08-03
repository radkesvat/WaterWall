#include "structure.h"

api_result_t vlessserverTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    return tunnelapiRecycleMessage(message);
}
