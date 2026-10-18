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
    char                               token[kAuthenticationServerEditTokenChars + 1];
    authenticationserverEditTokenFormat(ack->request->instance_id, ack->request->revision + 1, token);
    authenticationserver_json_writer_t w = {.output      = (char *) sbufGetMutablePtr(ack->buffer),
                                            .capacity    = kAuthenticationServerPasswordAckCap,
                                            .deadline_ms = ack->call->deadline_ms};
    authenticationserverJsonText(&w, "{\"id\":");
    authenticationserverJsonU64(&w, ack->request->id);
    authenticationserverJsonText(&w, ",\"config_revision\":");
    authenticationserverJsonU64(&w, ack->request->revision + 1);
    authenticationserverJsonText(&w, ",\"edit_token\":");
    authenticationserverJsonString(&w, token);
    authenticationserverJsonText(&w, "}");
    if (w.timeout || w.overflow)
    {
        ack->error = w.timeout ? "timeout" : "response_too_large";
        return false;
    }
    sbufSetLength(ack->buffer, (uint32_t) w.used);
    return true;
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
            usersTryChangePreparedPasswordByIdentifier(&ts->store.users,
                                                       request->id,
                                                       request->password,
                                                       working_allowance,
                                                       context->deadline_ms,
                                                       preparePasswordChangeAcknowledgement,
                                                       &ack);
        if (result == kUsersPasswordOk)
        {
            /* This exact transaction already owns its complete ACK. Delivery
             * loss never rolls back the committed credentials or revision. */
            authenticationserverBumpConfigRevision(t);
        }
        else
            error = ack.error != NULL ? ack.error : authenticationserverPasswordChangeError(result);
    }
    rwlockWriteUnlock(&ts->state_lock);
    return error;
}
