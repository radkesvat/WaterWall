#include "AuthenticationServer/audit.h"
#include "AuthenticationServer/password_change.h"

api_result_t authenticationserverApiChangeUserPassword(tunnel_t *t, sbuf_t *message,
                                                       const node_api_call_context_t *context)
{
    authenticationserver_password_request_t request;
    const char                             *error = authenticationserverParsePasswordChange(message, context, &request);
    if (error != NULL)
    {
        authenticationserver_tstate_t *ts = tunnelGetState(t);
        authenticationserverAuditRecordApi(ts->audit,
                                           context,
                                           "change-user-password",
                                           request.id,
                                           0,
                                           kAuthenticationServerAuditFieldCredentials,
                                           error);
        return authenticationserverApiError(context, error);
    }

    buffer_pool_t    *pool = getCurrentWorkerBufferPool();
    buffer_pool_fit_t fit;
    sbuf_t           *ack      = NULL;
    const size_t      retained = usersPreparedPasswordChangeOwnedBytes(request.password);
    const size_t      commit   = usersPreparedPasswordChangeCommitBytes(request.password);
    if (context->max_response_body_size < kAuthenticationServerPasswordAckCap ||
        ! bufferpoolQueryBestFit(pool, kAuthenticationServerPasswordAckCap, 0, &fit))
        error = "response_too_large";
    else if (context->working_memory_allowance < kAuthenticationServerApiScratchCharge ||
             retained > context->working_memory_allowance - kAuthenticationServerApiScratchCharge ||
             fit.allocation_charge >
                 context->working_memory_allowance - kAuthenticationServerApiScratchCharge - retained ||
             commit > context->working_memory_allowance - kAuthenticationServerApiScratchCharge - retained -
                          fit.allocation_charge)
        error = "resource_limit";
    else if (authenticationserverApiExpired(context->deadline_ms))
        error = "timeout";
    else
    {
        ack                    = bufferpoolGetBestFit(pool, kAuthenticationServerPasswordAckCap, 0);
        const size_t allowance = context->working_memory_allowance - kAuthenticationServerApiScratchCharge - retained -
                                 fit.allocation_charge;
        error = authenticationserverApplyConditionalPasswordChange(t, &request, context, ack, allowance);
    }
    usersFreePreparedPasswordChange(request.password);
    if (error != NULL)
    {
        authenticationserver_tstate_t *ts = tunnelGetState(t);
        authenticationserverAuditRecordApi(ts->audit,
                                           context,
                                           "change-user-password",
                                           request.id,
                                           0,
                                           kAuthenticationServerAuditFieldCredentials,
                                           error);
        if (ack != NULL)
            bufferpoolReuseBuffer(pool, ack);
        return authenticationserverApiError(context, error);
    }
    return (api_result_t) {.result_code = kApiResultOk, .buffer = ack};
}
