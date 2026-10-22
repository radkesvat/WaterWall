#include "AuthenticationServer/audit.h"
#include "AuthenticationServer/config_create.h"
#include "loggers/network_logger.h"

const char *authenticationserverConfigCreateError(users_add_result_t result)
{
    switch (result)
    {
    case kUsersAddResultOk:
        return NULL;
    case kUsersAddResultInvalidArgument:
    case kUsersAddResultInvalidJson:
    case kUsersAddResultInvalidUser:
        return "invalid_request";
    case kUsersAddResultInvalidWireGuardAllowedIps:
        return "invalid_allowed_ips";
    case kUsersAddResultDuplicateId:
        return "id_exists";
    case kUsersAddResultDuplicateName:
        return "name_exists";
    case kUsersAddResultDuplicateSHA224:
    case kUsersAddResultDuplicateSHA256:
    case kUsersAddResultDuplicateUUID:
    case kUsersAddResultDuplicateWireGuardPublicKey:
        return "credentials_exist";
    case kUsersAddResultDuplicateWireGuardAllowedIps:
        return "allowed_ips_overlap";
    case kUsersAddResultBusy:
        return "busy";
    case kUsersAddResultResourceLimit:
        return "resource_limit";
    case kUsersAddResultTooLarge:
        return "user_too_large";
    case kUsersAddResultTimeout:
    case kUsersAddResultPrecommitRejected:
        return "timeout";
    case kUsersAddResultStorageUnavailable:
    case kUsersAddResultCreationFailed:
        return "creation_failed";
    }
    LOGF("AuthenticationServer: unexpected account creation result");
    abortProgramNow(1);
    return NULL;
}

typedef struct creation_acknowledgement_s
{
    const authenticationserver_tstate_t         *state;
    const authenticationserver_create_request_t *request;
    const node_api_call_context_t               *call;
    sbuf_t                                      *buffer;
    const char                                  *error;
} creation_acknowledgement_t;

static bool prepareCreateAcknowledgement(void *arg)
{
    creation_acknowledgement_t *ack = arg;
    ack->error                      = authenticationserverApiPrepareAck(ack->buffer,
                                                   kAuthenticationServerCreateAckCap,
                                                   ack->call->deadline_ms,
                                                   ack->request->id,
                                                   ack->state->api_instance_id,
                                                   ack->state->store.config_revision + 1);
    return ack->error == NULL;
}

const char *authenticationserverApplyCreate(tunnel_t *t, authenticationserver_create_request_t *request,
                                            const node_api_call_context_t *context, sbuf_t *ack_buffer,
                                            size_t growth_allowance)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    if (! rwlockTryWriteLock(&ts->state_lock))
        return "busy";
    const char *error = NULL;
    if (ts->store.config_revision == UINT64_MAX)
        error = "revision_exhausted";
    else
    {
        creation_acknowledgement_t ack    = {.state = ts, .request = request, .call = context, .buffer = ack_buffer};
        users_add_result_t         result = usersTryAddPreparedUserWithExportLimit(&ts->store.users,
                                                                           request->candidate,
                                                                           growth_allowance,
                                                                           ts->max_user_export_bytes,
                                                                           context->deadline_ms,
                                                                           prepareCreateAcknowledgement,
                                                                           &ack);
        if (result == kUsersAddResultOk)
        {
            /* All expected failures precede publication. The ACK names this
             * exact commit even if dispatch completion or delivery is late. */
            authenticationserverBumpConfigRevision(t);
            authenticationserverAuditRecordApi(ts->audit,
                                               context,
                                               "create-user",
                                               request->id,
                                               ts->store.config_revision,
                                               kAuthenticationServerAuditFieldAccount |
                                                   kAuthenticationServerAuditFieldCredentials,
                                               NULL);
        }
        else
            error = ack.error != NULL ? ack.error : authenticationserverConfigCreateError(result);
    }
    rwlockWriteUnlock(&ts->state_lock);
    return error;
}
