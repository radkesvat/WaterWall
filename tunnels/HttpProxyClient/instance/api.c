#include "structure.h"
api_result_t httpproxyclientTunnelApi(tunnel_t *t, sbuf_t *message)
{
    discard t;
    return tunnelapiRecycleMessage(message);
}
