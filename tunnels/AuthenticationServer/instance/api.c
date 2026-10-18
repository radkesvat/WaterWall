#include "AuthenticationServer/api.h"

bool authenticationserverRegisterApi(tunnel_t *t)
{
    static const node_api_operation_t operations[] = {{.name                  = "status",
                                                       .handler               = authenticationserverApiStatus,
                                                       .read_only             = true,
                                                       .request_content_type  = "application/json",
                                                       .response_content_type = "application/json",
                                                       .response_encoding     = kNodeApiEncodingUtf8,
                                                       .execution             = kNodeApiCallingWorker},
                                                      {.name                  = "get-user",
                                                       .handler               = authenticationserverApiGetUser,
                                                       .read_only             = true,
                                                       .request_content_type  = "application/json",
                                                       .response_content_type = "application/json",
                                                       .response_encoding     = kNodeApiEncodingUtf8,
                                                       .execution             = kNodeApiCallingWorker},
                                                      {.name                  = "list-users",
                                                       .handler               = authenticationserverApiListUsers,
                                                       .read_only             = true,
                                                       .request_content_type  = "application/json",
                                                       .response_content_type = "application/json",
                                                       .response_encoding     = kNodeApiEncodingUtf8,
                                                       .execution             = kNodeApiCallingWorker}};
    return nodeApiRegister(t, operations, sizeof(operations) / sizeof(*operations));
}

api_result_t authenticationserverTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    return tunnelapiRecycleMessage(message);
}
