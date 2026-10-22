#include "internal.h"

#include "loggers/network_logger.h"

static bool authenticationclientErrorEquals(const uint8_t *data, uint32_t length, const char *expected);

static void authenticationclientEscapeError(const uint8_t *data, uint32_t length, char output[528]);

static void authenticationclientHandleError(tunnel_t *t, line_t *l, uint8_t request_type, const uint8_t *data,
                                            uint32_t length);

static bool authenticationclientErrorEquals(const uint8_t *data, uint32_t length, const char *expected)
{
    return length == stringLength(expected) && memoryEqual(data, expected, length);
}

static void authenticationclientEscapeError(const uint8_t *data, uint32_t length, char output[528])
{
    static const char hex[] = "0123456789ABCDEF";
    size_t            at    = 0;
    const uint32_t    count = min(length, 128U);
    for (uint32_t i = 0; i < count; ++i)
    {
        const uint8_t byte = data[i];
        if (byte == '\\')
        {
            output[at++] = '\\';
            output[at++] = '\\';
        }
        else if (byte >= 0x20 && byte <= 0x7E)
            output[at++] = (char) byte;
        else
        {
            output[at++] = '\\';
            output[at++] = 'x';
            output[at++] = hex[byte >> 4];
            output[at++] = hex[byte & 15];
        }
    }
    if (length > count)
    {
        static const char marker[] = "...[truncated]";
        memoryCopy(output + at, marker, sizeof(marker) - 1U);
        at += sizeof(marker) - 1U;
    }
    output[at] = '\0';
}

static void authenticationclientHandleError(tunnel_t *t, line_t *l, uint8_t request_type, const uint8_t *data,
                                            uint32_t length)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    const bool continuity             = authenticationclientErrorEquals(data, length, "accounting-continuity-lost");
    const bool push                   = request_type == kAuthenticationClientRequestTypePushUserStats;
    const bool inconsistent           = (push || request_type == kAuthenticationClientRequestTypeGetAllUsers) &&
                              (authenticationclientErrorEquals(data, length, "usage-replay-conflict") ||
                               authenticationclientErrorEquals(data, length, "usage-sequence-invalid"));
    const bool credential_rejected = request_type == kAuthenticationClientRequestTypeAuthenticate &&
                                     authenticationclientErrorEquals(data, length, "authentication-failed");
    if (credential_rejected)
    {
        mutexLock(&ts->control_mutex);
        ts->auth_rejected = true;
        mutexUnlock(&ts->control_mutex);
    }
    const bool authentication = authenticationclientErrorEquals(data, length, "authentication-required");
    const bool denied         = push && authenticationclientErrorEquals(data, length, "stats-push-not-allowed");
    authenticationclientRecordFailure(t,
                                      continuity || inconsistent ? kAuthenticationClientFailureContinuity
                                      : credential_rejected      ? kAuthenticationClientFailureCredentialRejected
                                      : denied                   ? kAuthenticationClientFailureStatsPushDenied
                                      : push && ! authentication ? kAuthenticationClientFailureStatsPushRejected
                                                                 : kAuthenticationClientFailureRemoteError,
                                      request_type);
    char diagnostic[528]; /* 128 * 4, truncation marker and terminator. */
    authenticationclientEscapeError(data, length, diagnostic);
    LOGW("AuthenticationClient: request %u failed: %s", request_type, diagnostic);
    if ((continuity || inconsistent) && ! authentication)
    {
        mutexLock(&ts->control_mutex);
        if (ts->pending_batch != NULL || inconsistent || request_type == kAuthenticationClientRequestTypeGetUsersPage)
            ts->continuity_error = true;
        else if (continuity)
        {
            memoryZero(ts->accounting_epoch, sizeof(ts->accounting_epoch));
            ts->next_batch_sequence = 1;
            ts->last_ack_sequence   = 0;
            memoryZero(ts->last_ack_digest, sizeof(ts->last_ack_digest));
        }
        const bool stopped = ts->continuity_error;
        mutexUnlock(&ts->control_mutex);
        if (stopped)
        {
            authenticationclientRecordFailure(t, kAuthenticationClientFailureContinuity, request_type);
            LOGE("AuthenticationClient: accounting continuity error; retained batch requires reconciliation");
            authenticationclientCloseControlLine(t, l, true);
            return;
        }
    }
    else if (push && ! authentication)
    {
        mutexLock(&ts->control_mutex);
        ts->stats_push_refused = true;
        ts->stats_retry_not_before_ms =
            wloopNowMonotonicMS(getWorkerLoop(0)) +
            max((uint64_t) kAuthenticationClientStatsRefusalMinRetryMs, (uint64_t) ts->reconnect_interval_ms);
        mutexUnlock(&ts->control_mutex);
    }
    authenticationclientRecoverControlLine(t, l, true);
}

void authenticationclientHandleResponseFrame(tunnel_t *t, line_t *l, uint8_t response_type, uint32_t correlation_id,
                                             const uint8_t *data, uint32_t data_len, uint64_t config_revision,
                                             uint64_t stats_revision, uint64_t received_at_ms)
{
    authenticationclient_tstate_t *ts           = tunnelGetState(t);
    uint8_t                        request_type = 0;
    mutexLock(&ts->control_mutex);
    const bool found = authenticationclientPendingRemove(ts, correlation_id, &request_type);
    if (found)
    {
        authenticationclientMarkRequestInFlightLocked(ts, request_type, false);
        ts->remote_config_revision = config_revision;
        ts->remote_stats_revision  = stats_revision;
        if (++ts->remote_revision_generation == 0)
            ts->remote_revision_generation = 1;
    }
    const uint64_t generation = ts->remote_revision_generation;
    mutexUnlock(&ts->control_mutex);
    if (! found)
        return; /* A stale correlation cannot enroll or settle accounting. */
    authenticationclientUpdateRequestTimer(t);
    if (response_type == kAuthenticationClientResponseTypeError)
    {
        authenticationclientHandleError(t, l, request_type, data, data_len);
        return;
    }
    switch (request_type)
    {
    case kAuthenticationClientRequestTypeAuthenticate: {
        uint8_t decoded[64];
        if (response_type != kAuthenticationClientResponseTypeSession || data_len != 128 ||
            ! asciiHexDecodeBytes(data, 128, decoded, sizeof(decoded)))
        {
            authenticationclientRecordFailure(t, kAuthenticationClientFailureInvalidResponse, request_type);
            authenticationclientRecoverControlLine(t, l, true);
            return;
        }
        mutexLock(&ts->control_mutex);
        if (ts->accounting_epoch[0] != '\0' && ! memoryEqual(ts->accounting_epoch, data + 64, 64))
        {
            ts->continuity_error = true;
            mutexUnlock(&ts->control_mutex);
            authenticationclientRecordFailure(t, kAuthenticationClientFailureContinuity, request_type);
            authenticationclientCloseControlLine(t, l, true);
            return;
        }
        if (ts->accounting_epoch[0] == '\0')
        {
            memoryCopy(ts->accounting_epoch, data + 64, 64);
            ts->next_batch_sequence = 1;
            ts->last_ack_sequence   = 0;
            memoryZero(ts->last_ack_digest, sizeof(ts->last_ack_digest));
        }
        memoryCopy(ts->token, data, 64);
        ts->authenticated           = true;
        ts->auth_rejected           = false;
        ts->catchup_capture_needed  = true;
        ts->pull_requested          = true;
        ts->pull_required           = true;
        ts->last_auth_success_ms    = authenticationclientLocalTimeMS();
        ts->last_auth_success_valid = true;
        mutexUnlock(&ts->control_mutex);
        authenticationclientResumeSync(t);
        return;
    }
    case kAuthenticationClientRequestTypeGetAllUsers: {
        authenticationclient_failure_t failure = kAuthenticationClientFailureInvalidResponse;
        if (response_type == kAuthenticationClientResponseTypeUsers && ts->pending_batch == NULL)
            failure = authenticationclientAcceptUsersPage(
                t, data, data_len, config_revision, stats_revision, generation, received_at_ms);
        if (failure != kAuthenticationClientFailureNone)
        {
            authenticationclientRecordFailure(t, failure, request_type);
            if (failure == kAuthenticationClientFailureContinuity)
            {
                mutexLock(&ts->control_mutex);
                ts->continuity_error = true;
                mutexUnlock(&ts->control_mutex);
                authenticationclientCloseControlLine(t, l, true);
            }
            else
                authenticationclientRecoverControlLine(t, l, true);
            return;
        }
        break;
    }
    case kAuthenticationClientRequestTypePushUserStats:
        if (response_type != kAuthenticationClientResponseTypeOk ||
            ! authenticationclientAcknowledgeUsageBatch(t, data, data_len))
        {
            authenticationclientRecordFailure(t, kAuthenticationClientFailureInvalidResponse, request_type);
            authenticationclientRecoverControlLine(t, l, true);
            return;
        }
        break;
    case kAuthenticationClientRequestTypePing:
        if (response_type != kAuthenticationClientResponseTypePong)
        {
            authenticationclientRecordFailure(t, kAuthenticationClientFailureInvalidResponse, request_type);
            authenticationclientRecoverControlLine(t, l, true);
            return;
        }
        break;
    default:
        break;
    }
    if (! ts->staging.active && (ts->catchup_capture_needed || authenticationclientHasCatchup(ts)))
        authenticationclientScheduleSyncProgress(t);
    else
        authenticationclientResumeSync(t);
}
