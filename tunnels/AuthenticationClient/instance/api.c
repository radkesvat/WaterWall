#include "structure.h"

enum
{
    kStatusMaximumBodySize = 4096
};

static const char *boolean(bool value)
{
    return value ? "true" : "false";
}

static const char *stateName(authenticationclient_state_t state)
{
    switch (state)
    {
    case kAuthenticationClientStateStopped:
        return "stopped";
    case kAuthenticationClientStateConnecting:
        return "connecting";
    case kAuthenticationClientStateAuthenticating:
        return "authenticating";
    case kAuthenticationClientStateReady:
        return "ready";
    case kAuthenticationClientStateContinuityError:
        return "continuity_error";
    }
    assert(false);
    return "stopped";
}

static const char *blockingName(authenticationclient_blocking_reason_t reason)
{
    switch (reason)
    {
    case kAuthenticationClientBlockNone:
        return "none";
    case kAuthenticationClientBlockStopping:
        return "stopping";
    case kAuthenticationClientBlockNotStarted:
        return "not_started";
    case kAuthenticationClientBlockContinuity:
        return "continuity_error";
    case kAuthenticationClientBlockCredentialRejected:
        return "credential_rejection";
    case kAuthenticationClientBlockCacheClock:
        return "unusable_cache_or_clock";
    }
    assert(false);
    return "none";
}

static const char *failureName(authenticationclient_failure_t failure)
{
    switch (failure)
    {
    case kAuthenticationClientFailureNone:
        return "none";
    case kAuthenticationClientFailureTransportClosed:
        return "transport_closed";
    case kAuthenticationClientFailureTimeout:
        return "timeout";
    case kAuthenticationClientFailureCredentialRejected:
        return "credential_rejection";
    case kAuthenticationClientFailureContinuity:
        return "continuity_error";
    case kAuthenticationClientFailureInvalidResponse:
        return "invalid_response";
    case kAuthenticationClientFailureSyncLimit:
        return "sync_limit";
    case kAuthenticationClientFailureRemoteError:
        return "remote_error";
    case kAuthenticationClientFailureStatsPushDenied:
        return "stats_push_denied";
    case kAuthenticationClientFailureStatsPushRejected:
        return "stats_push_rejected";
    }
    assert(false);
    return "none";
}

static const char *operationName(uint8_t operation)
{
    switch (operation)
    {
    case kAuthenticationClientRequestTypeAuthenticate:
        return "authenticate";
    case kAuthenticationClientRequestTypeGetUsersPage:
        return "pull";
    case kAuthenticationClientRequestTypePushUserStats:
        return "push";
    case kAuthenticationClientRequestTypePing:
        return "ping";
    default:
        return "transport";
    }
}

static const char *syncPhase(const authenticationclient_status_t *s)
{
    if (s->stopping || ! s->started)
        return "stopped";
    if (s->continuity_error)
        return "continuity_error";
    if (! s->connected)
        return "connecting";
    if (! s->authenticated)
        return "authenticating";
    if (s->push_in_flight)
        return "pushing";
    if (s->pull_in_flight || s->traversal_active)
        return "pulling";
    if (s->unresolved_batch)
        return "replay_pending";
    if (s->pull_required)
        return "refresh_required";
    if (s->catchup_capture_needed)
        return "capture_pending";
    /* Capture publishes only owed entries; ACK clears the array when the last
     * obligation settles. Nonempty storage proves pending work at worker-0
     * callback boundaries, even though some retained slots may be settled. */
    if (s->retained_catchup_slots > s->orphan_debt_count)
        return "catchup_pending";
    if (s->push_requested || s->pull_requested)
        return "queued";
    if (s->orphan_debt_count != 0)
        return "orphan_debt";
    return "idle";
}

static api_result_t resultBody(const node_api_call_context_t *context, enum api_result_e code, const char *text,
                               size_t length)
{
    buffer_pool_t    *pool = getCurrentWorkerBufferPool();
    buffer_pool_fit_t fit;
    if (length > context->max_response_body_size || ! bufferpoolQueryBestFit(pool, length, 0, &fit) ||
        fit.allocation_charge > context->working_memory_allowance)
        return (api_result_t) {.result_code = kApiResultError};
    sbuf_t *buffer = bufferpoolGetBestFit(pool, (uint32_t) length, 0);
    sbufSetLength(buffer, (uint32_t) length);
    memoryCopy(sbufGetMutablePtr(buffer), text, length);
    return (api_result_t) {.result_code = code, .buffer = buffer};
}

static api_result_t statusApi(tunnel_t *t, sbuf_t *message, const node_api_call_context_t *context)
{
    assert(currentThreadOwnsWorker(0) && message != NULL && context != NULL);
    const size_t length = sbufGetLength(message);
    /* At most four lexical values bound the tree; its string storage and
     * parser scratch are conservatively charged before tree construction. */
    const bool parse_fits =
        context->working_memory_allowance >= 2048 && length <= (context->working_memory_allowance - 2048) / 4;
    cJSON *body =
        parse_fits ? configLexicalParseBoundedQuiet((const char *) sbufGetRawPtr(message), length, 2, 4) : NULL;
    bool valid = cJSON_IsObject(body), include_accounting = false;
    for (const cJSON *field = body != NULL ? body->child : NULL; valid && field != NULL; field = field->next)
    {
        if (field->string == NULL || strcmp(field->string, "include_accounting") != 0 || ! cJSON_IsBool(field))
            valid = false;
        else
            include_accounting = cJSON_IsTrue(field);
    }
    cJSON_Delete(body);
    bufferpoolReuseBuffer(getCurrentWorkerBufferPool(), message);
    if (! valid)
    {
        static const char explanation[] =
            "{\"error\":\"Expected an object with an optional Boolean include_accounting.\"}";
        return resultBody(context, kApiResultError, explanation, sizeof(explanation) - 1);
    }

    buffer_pool_fit_t output_fit;
    const bool        output_fits =
        bufferpoolQueryBestFit(getCurrentWorkerBufferPool(), kStatusMaximumBodySize, 0, &output_fit) &&
        output_fit.allocation_charge <= context->working_memory_allowance;
    authenticationclient_status_t snapshot;
    authenticationclientStatusSnapshot(t,
                                       include_accounting,
                                       output_fits ? context->working_memory_allowance - output_fit.allocation_charge
                                                   : 0,
                                       context->deadline_ms,
                                       &snapshot);
    char   text[kStatusMaximumBodySize];
    size_t used = 0;
#define APPEND(...)                                                                                                    \
    do                                                                                                                 \
    {                                                                                                                  \
        int written = snprintf(text + used, sizeof(text) - used, __VA_ARGS__);                                         \
        if (written < 0 || (size_t) written >= sizeof(text) - used)                                                    \
            return (api_result_t) {.result_code = kApiResultError};                                                    \
        used += (size_t) written;                                                                                      \
    } while (0)
#define BOOL(field) APPEND(",\"" #field "\":%s", boolean(snapshot.field))
#define U64(field)  APPEND(",\"" #field "\":\"%" PRIu64 "\"", snapshot.field)
#define STATUS_OPTIONAL(name, valid, value)                                                                            \
    do                                                                                                                 \
    {                                                                                                                  \
        if (valid)                                                                                                     \
            APPEND(",\"" name "\":\"%" PRIu64 "\"", value);                                                            \
        else                                                                                                           \
            APPEND(",\"" name "\":null");                                                                              \
    } while (0)
    APPEND("{\"state\":\"%s\",\"blocking_reason\":\"%s\",\"sync_phase\":\"%s\"",
           stateName(snapshot.state),
           blockingName(snapshot.blocking_reason),
           syncPhase(&snapshot));
    APPEND(",\"traffic_multiplier\":%" PRIu32 ".%03" PRIu32,
           snapshot.traffic_multiplier / kUserTrafficMultiplierScale,
           snapshot.traffic_multiplier % kUserTrafficMultiplierScale);
    BOOL(started);
    BOOL(stopping);
    BOOL(connected);
    BOOL(authenticated);
    BOOL(auth_rejected);
    BOOL(continuity_error);
    BOOL(users_loaded);
    BOOL(clock_loaded);
    BOOL(can_authenticate);
    BOOL(write_paused);
    BOOL(auth_in_flight);
    BOOL(pull_in_flight);
    BOOL(push_in_flight);
    BOOL(pull_requested);
    BOOL(pull_required);
    BOOL(push_requested);
    BOOL(traversal_active);
    U64(sync_staged_users);
    U64(sync_staged_bytes);
    U64(sync_total_users);
    APPEND(",\"sync_retry_streak\":%" PRIu32, snapshot.sync_retry_streak);
    U64(sync_retry_remaining_ms);
    APPEND(",\"sync_retry_failure\":\"%s\"", failureName(snapshot.sync_retry_failure));
    BOOL(first_usage_push_requested);
    BOOL(first_usage_push_deferred);
    BOOL(catchup_capture_needed);
    BOOL(reconnect_queued);
    BOOL(unresolved_batch);
    U64(users_count);
    U64(pending_request_count);
    U64(retained_catchup_slots);
    U64(orphan_debt_count);
    STATUS_OPTIONAL("batch_sequence", snapshot.unresolved_batch, snapshot.batch_sequence);
    U64(batch_entry_count);
    U64(batch_size);
    STATUS_OPTIONAL("retry_remaining_ms", snapshot.retry_deadline_valid, snapshot.retry_remaining_ms);
    STATUS_OPTIONAL("request_remaining_ms", snapshot.request_deadline_valid, snapshot.request_remaining_ms);
    U64(applied_config_revision);
    U64(applied_stats_revision);
    U64(applied_revision_generation);
    U64(remote_config_revision);
    U64(remote_stats_revision);
    U64(remote_revision_generation);
    STATUS_OPTIONAL("authentication_success_age_ms", snapshot.auth_success_valid, snapshot.auth_success_age_ms);
    STATUS_OPTIONAL("pull_success_age_ms", snapshot.pull_success_valid, snapshot.pull_success_age_ms);
    STATUS_OPTIONAL("usage_ack_success_age_ms", snapshot.ack_success_valid, snapshot.ack_success_age_ms);
    APPEND(",\"last_failure\":");
    if (snapshot.last_failure == kAuthenticationClientFailureNone)
        APPEND("null");
    else
        APPEND("{\"code\":\"%s\",\"operation\":\"%s\",\"age_ms\":\"%" PRIu64 "\"}",
               failureName(snapshot.last_failure),
               operationName(snapshot.last_failure_operation),
               snapshot.last_failure_age_ms);
    APPEND(",\"accounting_state\":\"%s\"",
           snapshot.accounting_state == kAuthenticationClientAccountingAvailable     ? "available"
           : snapshot.accounting_state == kAuthenticationClientAccountingUnavailable ? "unavailable"
                                                                                     : "not_requested");
    if (snapshot.accounting_state == kAuthenticationClientAccountingAvailable)
    {
        U64(locally_unacknowledged_upload_bytes);
        U64(locally_unacknowledged_download_bytes);
        U64(usage_user_count);
        U64(first_use_observation_count);
        BOOL(accounting_lower_bound);
        U64(sampling_started_ms);
        U64(sampling_finished_ms);
    }
    APPEND("}");
#undef STATUS_OPTIONAL
#undef U64
#undef BOOL
#undef APPEND
    return resultBody(context, kApiResultOk, text, used);
}

bool authenticationclientRegisterApi(tunnel_t *t)
{
    static const node_api_operation_t operations[] = {{.name                  = "status",
                                                       .handler               = statusApi,
                                                       .read_only             = true,
                                                       .request_content_type  = "application/json",
                                                       .response_content_type = "application/json",
                                                       .response_encoding     = kNodeApiEncodingUtf8,
                                                       .execution             = kNodeApiSpecifiedWorker,
                                                       .wid                   = 0}};
    return nodeApiRegister(t, operations, sizeof(operations) / sizeof(operations[0]));
}

api_result_t authenticationclientTunnelApi(tunnel_t *instance, sbuf_t *message)
{
    discard instance;
    return tunnelapiUnsupportedMessage(message);
}
