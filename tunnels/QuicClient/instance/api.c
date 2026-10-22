#include "structure.h"

api_result_t quicclientTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    return tunnelapiUnsupportedMessage(message);
}
