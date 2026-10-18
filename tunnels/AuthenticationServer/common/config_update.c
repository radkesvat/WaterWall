#include "AuthenticationServer/config_update.h"
#include "loggers/network_logger.h"

const char *authenticationserverConfigUpdateError(users_update_result_t result)
{
    switch (result)
    {
    case kUsersUpdateResultOk:
        return NULL;
    case kUsersUpdateResultInvalidArgument:
    case kUsersUpdateResultUnknownFields:
    case kUsersUpdateResultInvalidRecordStatInterval:
    case kUsersUpdateResultDuplicateUUID:
    case kUsersUpdateResultDuplicateWireGuardPublicKey:
    case kUsersUpdateResultPasswordUpdateFailed:
        return "invalid_request";
    case kUsersUpdateResultInvalidWireGuardAllowedIps:
        return "invalid_allowed_ips";
    case kUsersUpdateResultCapacityRejected:
    case kUsersUpdateResultResourceLimit:
        return "resource_limit";
    case kUsersUpdateResultUserNotFound:
        return "not_found";
    case kUsersUpdateResultDuplicateName:
        return "name_exists";
    case kUsersUpdateResultDuplicateWireGuardAllowedIps:
        return "allowed_ips_overlap";
    case kUsersUpdateResultBusy:
        return "busy";
    case kUsersUpdateResultTimeout:
    case kUsersUpdateResultPrecommitRejected:
        return "timeout";
    case kUsersUpdateResultRevisionExhausted:
        return "revision_exhausted";
    }
    LOGF("AuthenticationServer: unexpected configuration patch result");
    abortProgramNow(1);
    return NULL;
}

typedef struct acknowledgement_s
{
    const authenticationserver_update_request_t *request;
    const node_api_call_context_t               *call;
    sbuf_t                                      *buffer;
    const char                                  *error;
} acknowledgement_t;

static bool prepareAcknowledgement(void *arg)
{
    acknowledgement_t *ack = arg;
    char               token[kAuthenticationServerEditTokenChars + 1];
    authenticationserverEditTokenFormat(ack->request->instance_id, ack->request->revision + 1, token);
    authenticationserver_json_writer_t w = {.output      = (char *) sbufGetMutablePtr(ack->buffer),
                                            .capacity    = kAuthenticationServerUpdateAckCap,
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

const char *authenticationserverApplyConditionalUpdate(tunnel_t *t, authenticationserver_update_request_t *request,
                                                       const node_api_call_context_t *context, sbuf_t *ack_buffer,
                                                       size_t growth_allowance)
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
        acknowledgement_t     ack    = {.request = request, .call = context, .buffer = ack_buffer};
        users_update_result_t result = usersTryApplyPreparedConfigByIdentifier(
            &ts->store.users,
            request->id,
            request->patch,
            min(growth_allowance, (size_t) kAuthenticationServerUpdateGrowthCap),
            context->deadline_ms,
            prepareAcknowledgement,
            &ack);
        if (result == kUsersUpdateResultOk)
        {
            /* No fallible work, snapshots or deadline checks beyond commitment.
             * The prebuilt ACK names this transaction even if delivery is late. */
            authenticationserverBumpConfigRevision(t);
        }
        else
            error = ack.error != NULL ? ack.error : authenticationserverConfigUpdateError(result);
    }
    rwlockWriteUnlock(&ts->state_lock);
    return error;
}
