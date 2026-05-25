#include "modules/ping/ping.h"

#include "loggers/network_logger.h"

sbuf_t *authenticationserverPingHandle(
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
    tunnel_t     *t,
    line_t       *l,
    const uint8_t *request_data,
    uint32_t      request_data_len)
{
    static const char ping_request[]  = "ping";
    static const char pong_response[] = "pong";

    discard t;

    if (request_data_len != sizeof(ping_request) - 1U ||
        memoryCompare(request_data, ping_request, sizeof(ping_request) - 1U) != 0)
    {
        LOGW("AuthenticationServer: ping module received invalid %u-byte request data",
             (unsigned int) request_data_len);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-ping-request");
    }

    LOGD("AuthenticationServer: ping module returning pong response");
    return authenticationserverCreateResponseFrame(l,
                                                  kAuthenticationServerResponseTypePong,
                                                  correlation_id,
                                                  (const uint8_t *) pong_response,
                                                  (uint32_t) (sizeof(pong_response) - 1U));
}
