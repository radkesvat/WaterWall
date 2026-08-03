#include "structure.h"

#include "loggers/network_logger.h"

api_result_t authenticationclientTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    // AuthenticationClient exposes no API, but it still owns the request buffer.
    return tunnelapiUnsupportedMessage(message);
}
