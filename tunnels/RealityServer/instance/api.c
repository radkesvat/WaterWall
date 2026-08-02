#include "structure.h"

api_result_t realityserverTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    return tunnelapiUnsupportedMessage(message);
}
