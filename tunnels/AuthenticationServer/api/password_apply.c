#include "AuthenticationServer/audit.h"
#include "AuthenticationServer/password_change.h"
#include "loggers/network_logger.h"

const char *authenticationserverPasswordChangeError(users_password_result_t result)
{
    switch (result)
    {
    case kUsersPasswordOk:
        return NULL;
    case kUsersPasswordInvalidArgument:
        return "invalid_request";
    case kUsersPasswordBusy:
        return "busy";
    case kUsersPasswordNotFound:
        return "not_found";
    case kUsersPasswordResourceLimit:
        return "resource_limit";
    case kUsersPasswordTooLarge:
        return "user_too_large";
    case kUsersPasswordTimeout:
    case kUsersPasswordPrecommitRejected:
        return "timeout";
    case kUsersPasswordCredentialsExist:
        return "credentials_exist";
    case kUsersPasswordPreparationFailed:
        return "password_change_failed";
    }
    LOGF("AuthenticationServer: unexpected password change result");
    abortProgramNow(1);
    return NULL;
}

typedef struct password_change_acknowledgement_s
{
    const authenticationserver_password_request_t *request;
    const node_api_call_context_t                 *call;
    sbuf_t                                        *buffer;
    const char                                    *error;
} password_change_acknowledgement_t;

static bool preparePasswordChangeAcknowledgement(void *arg)
{
    password_change_acknowledgement_t *ack = arg;
    ack->error                             = authenticationserverApiPrepareAck(ack->buffer,
                                                   kAuthenticationServerPasswordAckCap,
                                                   ack->call->deadline_ms,
                                                   ack->request->id,
                                                   ack->request->instance_id,
                                                   ack->request->revision + 1);
    return ack->error == NULL;
}

const char *authenticationserverApplyConditionalPasswordChange(tunnel_t                                *t,
                                                               authenticationserver_password_request_t *request,
                                                               const node_api_call_context_t           *context,
                                                               sbuf_t *ack_buffer, size_t working_allowance)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    if (! rwlockTryWriteLock(&ts->state_lock))
        return "busy";
    const char *error = NULL;
    if (memcmp(ts->api_instance_id, request->instance_id, sizeof(request->instance_id)) != 0 ||
        ts->store.config_revision != request->revision)
        error = "conflict";
    else if (ts->store.config_revision == UINT64_MAX)
        error = "revision_exhausted";
    else
    {
        password_change_acknowledgement_t ack = {.request = request, .call = context, .buffer = ack_buffer};
        users_password_result_t           result =
            usersTryChangePreparedPasswordByIdentifierWithExportLimit(&ts->store.users,
                                                                      request->id,
                                                                      request->password,
                                                                      working_allowance,
                                                                      ts->max_user_export_bytes,
                                                                      context->deadline_ms,
                                                                      preparePasswordChangeAcknowledgement,
                                                                      &ack);
        if (result == kUsersPasswordOk)
        {
            /* This exact transaction already owns its complete ACK. Delivery
             * loss never rolls back the committed credentials or revision. */
            authenticationserverBumpConfigRevision(t);
            authenticationserverAuditRecordApi(ts->audit,
                                               context,
                                               "change-user-password",
                                               request->id,
                                               ts->store.config_revision,
                                               kAuthenticationServerAuditFieldCredentials,
                                               NULL);
        }
        else
            error = ack.error != NULL ? ack.error : authenticationserverPasswordChangeError(result);
    }
    rwlockWriteUnlock(&ts->state_lock);
    return error;
}
