#include "AuthenticationServer/audit.h"
#include "AuthenticationServer/config_update.h"

api_result_t authenticationserverApiUpdateUser(tunnel_t *t, sbuf_t *message, const node_api_call_context_t *context)
{
    authenticationserver_update_request_t request;
    const char                           *error = authenticationserverParseUpdate(message, context, &request);
    if (error != NULL)
    {
        authenticationserver_tstate_t *ts = tunnelGetState(t);
        authenticationserverAuditRecordApi(
            ts->audit, context, "update-user", request.id, 0, request.audit_fields, error);
        return authenticationserverApiError(context, error);
    }

    buffer_pool_t    *pool = getCurrentWorkerBufferPool();
    buffer_pool_fit_t fit;
    sbuf_t           *ack      = NULL;
    size_t            retained = usersPreparedConfigPatchOwnedBytes(request.patch);
    if (context->max_response_body_size < kAuthenticationServerUpdateAckCap ||
        ! bufferpoolQueryBestFit(pool, kAuthenticationServerUpdateAckCap, 0, &fit))
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
        ack              = bufferpoolGetBestFit(pool, kAuthenticationServerUpdateAckCap, 0);
        size_t allowance = context->working_memory_allowance - kAuthenticationServerApiScratchCharge - retained -
                           fit.allocation_charge;
        error = authenticationserverApplyConditionalUpdate(t, &request, context, ack, allowance);
    }
    usersFreePreparedConfigPatch(request.patch);
    if (error != NULL)
    {
        authenticationserver_tstate_t *ts = tunnelGetState(t);
        authenticationserverAuditRecordApi(
            ts->audit, context, "update-user", request.id, 0, request.audit_fields, error);
        if (ack != NULL)
            bufferpoolReuseBuffer(pool, ack);
        return authenticationserverApiError(context, error);
    }
    return (api_result_t) {.result_code = kApiResultOk, .buffer = ack};
}
