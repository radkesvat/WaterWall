#include "AuthenticationServer/audit.h"
#include "AuthenticationServer/config_create.h"

api_result_t authenticationserverApiCreateUser(tunnel_t *t, sbuf_t *message, const node_api_call_context_t *context)
{
    authenticationserver_create_request_t request;
    const char                           *error = authenticationserverParseCreate(message, context, &request);
    if (error != NULL)
    {
        authenticationserver_tstate_t *ts = tunnelGetState(t);
        authenticationserverAuditRecordApi(ts->audit,
                                           context,
                                           "create-user",
                                           request.id,
                                           0,
                                           kAuthenticationServerAuditFieldAccount |
                                               kAuthenticationServerAuditFieldCredentials,
                                           error);
        return authenticationserverApiError(context, error);
    }

    buffer_pool_t    *pool = getCurrentWorkerBufferPool();
    buffer_pool_fit_t fit;
    sbuf_t           *ack      = NULL;
    size_t            retained = usersPreparedNewUserOwnedBytes(request.candidate);
    if (context->max_response_body_size < kAuthenticationServerCreateAckCap ||
        ! bufferpoolQueryBestFit(pool, kAuthenticationServerCreateAckCap, 0, &fit))
        error = "response_too_large";
    else if (context->working_memory_allowance < kAuthenticationServerApiScratchCharge ||
             retained > context->working_memory_allowance - kAuthenticationServerApiScratchCharge ||
             fit.allocation_charge >
                 context->working_memory_allowance - kAuthenticationServerApiScratchCharge - retained)
        error = "resource_limit";
    else if (authenticationserverApiExpired(context->deadline_ms))
        error = "timeout";
    else
    {
        ack              = bufferpoolGetBestFit(pool, kAuthenticationServerCreateAckCap, 0);
        size_t allowance = context->working_memory_allowance - kAuthenticationServerApiScratchCharge - retained -
                           fit.allocation_charge;
        error = authenticationserverApplyCreate(t, &request, context, ack, allowance);
    }
    usersFreePreparedNewUser(request.candidate);
    if (error != NULL)
    {
        authenticationserver_tstate_t *ts = tunnelGetState(t);
        authenticationserverAuditRecordApi(ts->audit,
                                           context,
                                           "create-user",
                                           request.id,
                                           0,
                                           kAuthenticationServerAuditFieldAccount |
                                               kAuthenticationServerAuditFieldCredentials,
                                           error);
        if (ack != NULL)
            bufferpoolReuseBuffer(pool, ack);
        return authenticationserverApiError(context, error);
    }
    return (api_result_t) {.result_code = kApiResultOk, .buffer = ack};
}
