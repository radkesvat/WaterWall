#include "interface.h"

api_result_t streamfragmenterTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    return tunnelapiRecycleMessage(message);
}
