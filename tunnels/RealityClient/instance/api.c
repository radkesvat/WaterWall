#include "structure.h"

api_result_t realityclientTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    return tunnelapiUnsupportedMessage(message);
}
