#include "internal.h"

#include "loggers/network_logger.h"

static bool authenticationclientPendingReserve(authenticationclient_tstate_t *ts, uint32_t count);

static bool authenticationclientPendingFindTimedOutLocked(authenticationclient_tstate_t *ts, uint64_t now_ms,
                                                          authenticationclient_pending_request_t *pending_out);

static bool authenticationclientPendingReserve(authenticationclient_tstate_t *ts, uint32_t count)
{
    if (LIKELY(count <= ts->pending_capacity))
    {
        return true;
    }

    uint32_t new_capacity = ts->pending_capacity == 0 ? 8U : ts->pending_capacity;
    while (new_capacity < count)
    {
        if (UNLIKELY(new_capacity > UINT32_MAX / 2U))
        {
            return false;
        }
        new_capacity *= 2U;
    }
    if (UNLIKELY(new_capacity > ts->max_pending_requests))
    {
        new_capacity = ts->max_pending_requests;
    }
    if (UNLIKELY(new_capacity < count))
    {
        return false;
    }

    size_t bytes;
    if (UNLIKELY(! memoryTryComputeArraySize(new_capacity, sizeof(*ts->pending_requests), &bytes)))
        return false;
    authenticationclient_pending_request_t *new_items = memoryReAllocate(ts->pending_requests, bytes);

    ts->pending_requests = new_items;
    ts->pending_capacity = new_capacity;
    return true;
}

bool authenticationclientPendingAppend(authenticationclient_tstate_t *ts, uint32_t correlation_id, uint8_t request_type,
                                       uint64_t created_at_ms)
{
    if (UNLIKELY(ts->pending_count >= ts->max_pending_requests))
    {
        return false;
    }
    if (UNLIKELY(! authenticationclientPendingReserve(ts, ts->pending_count + 1U)))
    {
        return false;
    }

    ts->pending_requests[ts->pending_count] = (authenticationclient_pending_request_t) {
        .correlation_id = correlation_id, .created_at_ms = created_at_ms, .request_type = request_type};
    ts->pending_count += 1U;
    return true;
}

static bool authenticationclientPendingFindTimedOutLocked(authenticationclient_tstate_t *ts, uint64_t now_ms,
                                                          authenticationclient_pending_request_t *pending_out)
{
    if (UNLIKELY(ts->request_timeout_ms == 0))
    {
        return false;
    }

    for (uint32_t i = 0; i < ts->pending_count; ++i)
    {
        const authenticationclient_pending_request_t *pending = &ts->pending_requests[i];
        if (UNLIKELY(now_ms >= pending->created_at_ms + ts->request_timeout_ms))
        {
            *pending_out = *pending;
            return true;
        }
    }

    return false;
}

bool authenticationclientPendingRemove(authenticationclient_tstate_t *ts, uint32_t correlation_id,
                                       uint8_t *request_type_out)
{
    for (uint32_t i = 0; i < ts->pending_count; ++i)
    {
        authenticationclient_pending_request_t *pending = &ts->pending_requests[i];
        if (pending->correlation_id != correlation_id)
        {
            continue;
        }

        *request_type_out       = pending->request_type;
        ts->pending_requests[i] = ts->pending_requests[ts->pending_count - 1U];
        ts->pending_count -= 1U;
        return true;
    }

    return false;
}

void authenticationclientMarkRequestInFlightLocked(authenticationclient_tstate_t *ts, uint8_t request_type,
                                                   bool in_flight)
{
    switch (request_type)
    {
    case kAuthenticationClientRequestTypeAuthenticate:
        ts->auth_in_flight = in_flight;
        break;
    case kAuthenticationClientRequestTypeGetAllUsers:
        ts->pull_in_flight = in_flight;
        break;
    case kAuthenticationClientRequestTypePushUserStats:
        ts->push_in_flight = in_flight;
        break;
    default:
        break;
    }
}

void authenticationclientRemovePendingById(tunnel_t *t, uint32_t correlation_id)
{
    authenticationclient_tstate_t *ts           = tunnelGetState(t);
    uint8_t                        request_type = 0;

    mutexLock(&ts->control_mutex);
    if (LIKELY(authenticationclientPendingRemove(ts, correlation_id, &request_type)))
    {
        authenticationclientMarkRequestInFlightLocked(ts, request_type, false);
    }
    mutexUnlock(&ts->control_mutex);
    authenticationclientUpdateRequestTimer(t);
}

bool authenticationclientCloseTimedOutControlLine(tunnel_t *t)
{
    authenticationclient_tstate_t         *ts      = tunnelGetState(t);
    authenticationclient_pending_request_t pending = {0};
    line_t                                *line    = NULL;
    const uint64_t                         now_ms  = wloopNowMonotonicMS(getWorkerLoop(0));

    mutexLock(&ts->control_mutex);
    if (UNLIKELY(ts->control_line != NULL && lineIsAlive(ts->control_line) &&
                 authenticationclientPendingFindTimedOutLocked(ts, now_ms, &pending)))
    {
        line = ts->control_line;
        lineRef(line);
    }
    mutexUnlock(&ts->control_mutex);

    if (LIKELY(line == NULL))
    {
        return false;
    }

    LOGW("AuthenticationClient: request type %u with correlation id %u timed out after %" PRIu64 " ms; reconnecting",
         (unsigned int) pending.request_type,
         (unsigned int) pending.correlation_id,
         now_ms - pending.created_at_ms);

    authenticationclientRecordFailure(t, kAuthenticationClientFailureTimeout, pending.request_type);
    authenticationclientRecoverControlLine(t, line, true);
    lineUnref(line);
    return true;
}
