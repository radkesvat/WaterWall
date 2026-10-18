#include "../../Internals/AuthenticationCommon/stream.h"
#include "structure.h"

#include "loggers/network_logger.h"
#include "node_builder/config_lexical.h"

static void authenticationclientWriteNetworkUI32(uint8_t *dest, uint32_t value)
{
    uint32_t network_value = htonl(value);
    sbufByteCopy(dest, &network_value, (uint32_t) sizeof(network_value));
}

static uint32_t authenticationclientReadNetworkUI32(const uint8_t *src)
{
    uint32_t network_value = 0;
    sbufByteCopy(&network_value, src, (uint32_t) sizeof(network_value));
    return ntohl(network_value);
}

static uint64_t authenticationclientReadNetworkUI64(const uint8_t *src)
{
    return ((uint64_t) src[0] << 56U) | ((uint64_t) src[1] << 48U) | ((uint64_t) src[2] << 40U) |
           ((uint64_t) src[3] << 32U) | ((uint64_t) src[4] << 24U) | ((uint64_t) src[5] << 16U) |
           ((uint64_t) src[6] << 8U) | (uint64_t) src[7];
}

static const char *authenticationclientRequestTypeName(uint8_t request_type)
{
    switch (request_type)
    {
    case kAuthenticationClientRequestTypePing:
        return "Ping";
    case kAuthenticationClientRequestTypeGetUserBySHA256Hex:
        return "GetUserBySHA256Hex";
    case kAuthenticationClientRequestTypeGetUserBySHA256Base64:
        return "GetUserBySHA256Base64";
    case kAuthenticationClientRequestTypeGetUserBySHA256:
        return "GetUserBySHA256";
    case kAuthenticationClientRequestTypeGetUserBySHA224Hex:
        return "GetUserBySHA224Hex";
    case kAuthenticationClientRequestTypeGetUserBySHA224Base64:
        return "GetUserBySHA224Base64";
    case kAuthenticationClientRequestTypeGetUserBySHA224:
        return "GetUserBySHA224";
    case kAuthenticationClientRequestTypeGetUserByPassword:
        return "GetUserByPassword";
    case kAuthenticationClientRequestTypeAddNewUser:
        return "AddNewUser";
    case kAuthenticationClientRequestTypeUpdateUser:
        return "UpdateUser";
    case kAuthenticationClientRequestTypeGetAllUsers:
        return "GetAllUsers";
    case kAuthenticationClientRequestTypeAuthenticate:
        return "Authenticate";
    case kAuthenticationClientRequestTypePushUserStats:
        return "PushUserStats";
    default:
        return "Unknown";
    }
}

static const char *authenticationclientResponseTypeName(uint8_t response_type)
{
    switch (response_type)
    {
    case kAuthenticationClientResponseTypeOk:
        return "Ok";
    case kAuthenticationClientResponseTypeError:
        return "Error";
    case kAuthenticationClientResponseTypePong:
        return "Pong";
    case kAuthenticationClientResponseTypeUser:
        return "User";
    case kAuthenticationClientResponseTypeUsers:
        return "Users";
    case kAuthenticationClientResponseTypeSession:
        return "Session";
    default:
        return "Unknown";
    }
}

static void authenticationclientCorrelationIdWrite(uint8_t dest[kAuthenticationClientCorrelationIdSize], uint32_t value)
{
    authenticationclientWriteNetworkUI32(dest, value);
}

static uint32_t authenticationclientCorrelationIdRead(const uint8_t src[kAuthenticationClientCorrelationIdSize])
{
    return authenticationclientReadNetworkUI32(src);
}

static void authenticationclientDestroyUsers(users_t *users)
{
    if (UNLIKELY(users == NULL))
    {
        return;
    }

    usersDestroy(users);
    memoryFreeAligned(users);
}

static users_t *authenticationclientCreateUsersCopy(const users_t *src)
{
    if (UNLIKELY(src == NULL))
    {
        return NULL;
    }

    /* users_t snapshots are aligned-allocated; always release them with authenticationclientDestroyUsers(). */
    users_t *copy = memoryAllocateAligned(sizeof(*copy), 32);
    if (UNLIKELY(! usersCreate(copy)))
    {
        memoryFreeAligned(copy);
        return NULL;
    }

    /*
     * Native O(N) deep copy of the local sync baseline. Only the received
     * network response still needs a JSON parse into the active table; the local
     * baseline no longer round-trips through JSON.
     */
    if (UNLIKELY(! usersCopy(copy, src)))
    {
        authenticationclientDestroyUsers(copy);
        return NULL;
    }

    return copy;
}

static bool authenticationclientUsersHaveRequiredIds(const users_t *users)
{
    const size_t count = usersCount(users);
    for (size_t i = 0; i < count; ++i)
    {
        const user_t *user = usersGetAtConst(users, i);
        if (UNLIKELY(user == NULL || user->id == 0))
        {
            LOGW("AuthenticationClient: GetAllUsers returned user at index %zu without a required non-zero id", i);
            return false;
        }
    }

    return true;
}

static uint64_t authenticationclientCounterDelta(uint64_t current, uint64_t baseline)
{
    return current > baseline ? current - baseline : 0;
}

static user_t *authenticationclientLookupUserByStableId(users_t *users, const user_t *reference)
{
    if (users == NULL || reference == NULL)
    {
        return NULL;
    }
    if (reference->id != 0)
    {
        return usersLookupByIdentifier(users, reference->id);
    }
    return NULL;
}

static users_update_result_t authenticationclientAddTrafficByStableId(users_t *users, const user_t *reference,
                                                                      uint64_t upload_delta, uint64_t download_delta)
{
    if (reference->id != 0)
    {
        return usersAddTrafficByIdentifier(users, reference->id, upload_delta, download_delta);
    }
    return kUsersUpdateResultInvalidArgument;
}

static void authenticationclientInstallClientClocks(users_t *users, uint64_t server_time_ms,
                                                    uint64_t accounting_time_ms, uint64_t received_at_ms)
{
    for (size_t i = 0; i < usersCount(users); ++i)
        userInstallClientClock(usersGetAt(users, i), server_time_ms, accounting_time_ms, received_at_ms);
}

static void authenticationclientClearSessionLocked(authenticationclient_tstate_t *ts)
{
    memoryZero(ts->token, sizeof(ts->token));
    ts->authenticated              = false;
    ts->auth_in_flight             = false;
    ts->pull_in_flight             = false;
    ts->push_in_flight             = false;
    ts->pull_requested             = true;
    ts->pull_required              = true;
}

static void authenticationclientResetFirstUsagePushRuntime(tunnel_t *t)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);

    rwlockReadLock(&ts->users_lock);
    if (ts->users != NULL)
    {
        usersResetFirstUsagePushRequests(ts->users);
    }
    rwlockReadUnlock(&ts->users_lock);
}

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

static bool authenticationclientPendingAppend(authenticationclient_tstate_t *ts, uint32_t correlation_id,
                                              uint8_t request_type, uint64_t created_at_ms)
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

static bool authenticationclientPendingRemove(authenticationclient_tstate_t *ts, uint32_t correlation_id,
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

static void authenticationclientMarkRequestInFlightLocked(authenticationclient_tstate_t *ts, uint8_t request_type,
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

static bool authenticationclientRequestMayBeSentLocked(authenticationclient_tstate_t *ts, uint8_t request_type)
{
    if (UNLIKELY(ts->stopping || ts->continuity_error || ! ts->connected || ts->write_paused ||
                 ts->control_line == NULL))
    {
        return false;
    }

    if (request_type == kAuthenticationClientRequestTypeAuthenticate)
    {
        return ! ts->authenticated && ! ts->auth_in_flight;
    }
    if (! ts->authenticated)
    {
        return false;
    }
    if (request_type == kAuthenticationClientRequestTypeGetAllUsers)
    {
        return ! ts->pull_in_flight && ! ts->push_in_flight && ts->pending_batch == NULL;
    }
    if (request_type == kAuthenticationClientRequestTypePushUserStats)
    {
        return ! ts->push_in_flight && ! ts->pull_in_flight && ts->accounting_epoch[0] != '\0' &&
               (ts->pending_batch != NULL || ! ts->pull_required);
    }
    return true;
}

static void authenticationclientRemovePendingById(tunnel_t *t, uint32_t correlation_id)
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

static sbuf_t *authenticationclientCreateRequestMessage(line_t *l, uint8_t request_type, uint32_t correlation_id,
                                                        const uint8_t *request_data, uint32_t request_data_len,
                                                        const uint8_t token[kAuthenticationClientSessionTokenSize])
{
    const uint32_t frame_len   = kAuthenticationClientRequestHeaderSize + request_data_len;
    const uint32_t message_len = kAuthenticationClientRequestEnvelopeHeaderSize + frame_len;

    // Protocol limits are intentionally far below UINT32_MAX; revisit if those limits grow.
    if (UNLIKELY(request_data_len > kAuthenticationClientMaxRequestData ||
                 frame_len > kAuthenticationClientMaxMessagePayload))
    {
        LOGW("AuthenticationClient: refused oversized request type %u", (unsigned int) request_type);
        return NULL;
    }

    sbuf_t *message = bufferpoolGetLargeBuffer(lineGetBufferPool(l));
    message         = sbufReserveSpace(message, message_len);
    sbufSetLength(message, message_len);

    uint8_t *ptr = sbufGetMutablePtr(message);
    authenticationclientWriteNetworkUI32(ptr, message_len - kAuthenticationClientMessageHeaderSize);
    memoryCopy(ptr + kAuthenticationClientMessageHeaderSize, token, kAuthenticationClientSessionTokenSize);

    uint8_t *frame = ptr + kAuthenticationClientRequestEnvelopeHeaderSize;
    frame[0]       = request_type;
    authenticationclientCorrelationIdWrite(frame + 1, correlation_id);
    authenticationclientWriteNetworkUI32(frame + 1 + kAuthenticationClientCorrelationIdSize, request_data_len);
    if (request_data_len > 0)
    {
        memoryCopy(frame + kAuthenticationClientRequestHeaderSize, request_data, request_data_len);
    }

    return message;
}

static bool authenticationclientSendRequest(tunnel_t *t, uint8_t request_type, const uint8_t *request_data,
                                            uint32_t request_data_len)
{
    authenticationclient_tstate_t *ts                                           = tunnelGetState(t);
    uint8_t                        token[kAuthenticationClientSessionTokenSize] = {0};
    uint32_t                       correlation_id                               = 0;
    uint64_t                       now_ms                                       = wloopNowMonotonicMS(getWorkerLoop(0));

    line_t *line = NULL;

    mutexLock(&ts->control_mutex);
    if (UNLIKELY(! authenticationclientRequestMayBeSentLocked(ts, request_type)))
    {
        if (ts->verbose)
        {
            LOGD("AuthenticationClient: not sending %s request; started=%s stopping=%s connected=%s "
                 "authenticated=%s write-paused=%s control-line=%s",
                 authenticationclientRequestTypeName(request_type),
                 boolToTrueFalse(ts->started),
                 boolToTrueFalse(ts->stopping),
                 boolToTrueFalse(ts->connected),
                 boolToTrueFalse(ts->authenticated),
                 boolToTrueFalse(ts->write_paused),
                 ts->control_line != NULL ? "present" : "none");
        }
        mutexUnlock(&ts->control_mutex);
        return false;
    }

    correlation_id = ts->next_correlation_id++;
    if (UNLIKELY(ts->next_correlation_id == 0))
    {
        ts->next_correlation_id = 1U;
    }

    if (UNLIKELY(! authenticationclientPendingAppend(ts, correlation_id, request_type, now_ms)))
    {
        mutexUnlock(&ts->control_mutex);
        LOGW("AuthenticationClient: pending request table is full");
        return false;
    }
    authenticationclientMarkRequestInFlightLocked(ts, request_type, true);

    if (request_type != kAuthenticationClientRequestTypeAuthenticate)
    {
        memoryCopy(token, ts->token, sizeof(token));
    }

    if (LIKELY(ts->control_line != NULL && lineIsAlive(ts->control_line)))
    {
        line = ts->control_line;
        lineRef(line);
    }
    mutexUnlock(&ts->control_mutex);

    authenticationclientUpdateRequestTimer(t);
    if (UNLIKELY(line == NULL))
    {
        if (ts->verbose)
        {
            LOGD("AuthenticationClient: no live control line for %s request correlation-id=%u",
                 authenticationclientRequestTypeName(request_type),
                 (unsigned int) correlation_id);
        }
        authenticationclientRemovePendingById(t, correlation_id);

        return false;
    }

    sbuf_t *message = authenticationclientCreateRequestMessage(
        line, request_type, correlation_id, request_data, request_data_len, token);
    if (UNLIKELY(message == NULL))
    {
        authenticationclientRemovePendingById(t, correlation_id);

        lineUnref(line);
        return false;
    }

    if (ts->verbose)
    {
        LOGD("AuthenticationClient: sending %s request correlation-id=%u payload=%u",
             authenticationclientRequestTypeName(request_type),
             (unsigned int) correlation_id,
             (unsigned int) request_data_len);
    }

    tunnelNextUpStreamPayload(t, line, message);
    bool alive = lineIsAlive(line);
    if (UNLIKELY(! alive) && ts->verbose)
    {
        LOGD("AuthenticationClient: control line closed while sending %s request correlation-id=%u",
             authenticationclientRequestTypeName(request_type),
             (unsigned int) correlation_id);
    }
    lineUnref(line);
    return alive;
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

static bool authenticationclientShouldSendGetAllUsers(tunnel_t *t, bool pull_due)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);

    uint64_t remote_config_revision     = 0;
    uint64_t remote_stats_revision      = 0;
    uint64_t remote_revision_generation = 0;

    mutexLock(&ts->control_mutex);
    remote_config_revision     = ts->remote_config_revision;
    remote_stats_revision      = ts->remote_stats_revision;
    remote_revision_generation = ts->remote_revision_generation;
    mutexUnlock(&ts->control_mutex);

    uint64_t local_config_revision     = 0;
    uint64_t local_stats_revision      = 0;
    uint64_t local_revision_generation = 0;
    bool     users_loaded              = false;

    rwlockReadLock(&ts->users_lock);
    local_config_revision     = ts->local_config_revision;
    local_stats_revision      = ts->local_stats_revision;
    local_revision_generation = ts->local_revision_generation;
    users_loaded              = ts->users_loaded;
    rwlockReadUnlock(&ts->users_lock);

    if (! users_loaded)
    {
        return true;
    }
    if (remote_revision_generation == 0)
    {
        return pull_due;
    }
    if (local_revision_generation == 0)
    {
        return true;
    }
    if (remote_config_revision != local_config_revision || remote_stats_revision != local_stats_revision)
    {
        return true;
    }

    return pull_due && remote_revision_generation == local_revision_generation;
}

static bool authenticationclientSendJsonRequest(tunnel_t *t, uint8_t request_type, cJSON *json)
{
    char *text = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (UNLIKELY(text == NULL))
    {
        return false;
    }

    bool ok = authenticationclientSendRequest(t, request_type, (const uint8_t *) text, (uint32_t) stringLength(text));
    cJSON_free(text);
    return ok;
}

bool authenticationclientSendAuthenticate(tunnel_t *t)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);

    cJSON *json = cJSON_CreateObject();
    discard cJSON_AddStringToObject(json, "name", ts->name);
    discard cJSON_AddStringToObject(json, "secret", ts->secret);
    if (ts->accounting_epoch[0] != '\0')
        discard cJSON_AddStringToObject(json, "epoch", ts->accounting_epoch);

    return authenticationclientSendJsonRequest(t, kAuthenticationClientRequestTypeAuthenticate, json);
}

bool authenticationclientSendPing(tunnel_t *t)
{
    static const char ping_request[] = "ping";

    return authenticationclientSendRequest(t,
                                           kAuthenticationClientRequestTypePing,
                                           (const uint8_t *) ping_request,
                                           (uint32_t) (sizeof(ping_request) - 1U));
}

bool authenticationclientSendGetAllUsers(tunnel_t *t)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    mutexLock(&ts->control_mutex);
    ts->pull_requested = true;
    const bool allowed = authenticationclientRequestMayBeSentLocked(ts, kAuthenticationClientRequestTypeGetAllUsers);
    if (allowed)
        ts->pull_requested = false;
    mutexUnlock(&ts->control_mutex);
    if (! allowed)
        return false;
    const bool sent = authenticationclientSendRequest(t, kAuthenticationClientRequestTypeGetAllUsers, NULL, 0);
    if (! sent)
    {
        mutexLock(&ts->control_mutex);
        ts->pull_requested = true;
        mutexUnlock(&ts->control_mutex);
        authenticationclientScheduleSyncProgress(t);
    }
    return sent;
}

static int authenticationclientCompareEntries(const void *left, const void *right)
{
    const authenticationclient_accounting_entry_t *a = left, *b = right;
    return (a->id > b->id) - (a->id < b->id);
}

static authenticationclient_accounting_entry_t *authenticationclientCatchupEntry(authenticationclient_tstate_t *ts,
                                                                                 uint64_t                       id)
{
    const authenticationclient_accounting_entry_t key = {.id = id};
    return ts->catchup_entries_count == 0 ? NULL
                                          : bsearch(&key,
                                                    ts->catchup_entries,
                                                    ts->catchup_entries_count,
                                                    sizeof(key),
                                                    authenticationclientCompareEntries);
}

static bool authenticationclientEntryOwed(const authenticationclient_accounting_entry_t *entry)
{
    return entry->delta.u != 0 || entry->delta.d != 0 || entry->first_usage_at_ms != 0;
}

static bool authenticationclientHasCatchup(const authenticationclient_tstate_t *ts)
{
    for (size_t i = 0; i < ts->catchup_entries_count; ++i)
        if (authenticationclientEntryOwed(&ts->catchup_entries[i]))
            return true;
    return false;
}

/* users_lock pins active and baseline tables. Generic copies deliberately omit
 * evidence, so reporting takes explicit coherent user/traffic value snapshots. */
static user_ud_t authenticationclientOwedTraffic(authenticationclient_tstate_t    *ts,
                                                 const user_accounting_snapshot_t *snapshot)
{
    user_stat_t previous = {0};
    user_t     *base     = usersLookupByIdentifier(ts->sync_baseline_users, snapshot->id);
    if (base != NULL)
        userGetStats(base, &previous);
    return (user_ud_t) {.u = authenticationclientCounterDelta(snapshot->traffic.u, previous.traffic.u),
                        .d = authenticationclientCounterDelta(snapshot->traffic.d, previous.traffic.d)};
}

static bool authenticationclientCaptureCatchup(tunnel_t *t)
{
    authenticationclient_tstate_t *ts       = tunnelGetState(t);
    user_accounting_snapshot_t    *snapshot = NULL;
    size_t                         count    = 0, bytes;
    rwlockReadLock(&ts->users_lock);
    if (! usersSnapshotAccounting(ts->users, &snapshot, &count) ||
        ! memoryTryComputeArraySize(count, sizeof(*ts->catchup_entries), &bytes))
    {
        rwlockReadUnlock(&ts->users_lock);
        memoryFree(snapshot);
        return false;
    }
    authenticationclient_accounting_entry_t *entries = memoryAllocate(bytes);
    size_t                                   owed    = 0;
    for (size_t i = 0; i < count; ++i)
    {
        const user_accounting_snapshot_t       *current = &snapshot[i];
        authenticationclient_accounting_entry_t entry   = {
              .id                = current->id,
              .delta             = authenticationclientOwedTraffic(ts, current),
              .first_usage_at_ms = current->observation_pending ? current->first_usage_at_ms : 0};
        const authenticationclient_accounting_entry_t *retained = authenticationclientCatchupEntry(ts, current->id);
        if (retained != NULL)
        {
            /* Reconnect must preserve debt hidden by a saturated rebase.
             * Visible A - B overlaps that debt, so merge without adding it twice. */
            entry.delta.u = max(entry.delta.u, retained->delta.u);
            entry.delta.d = max(entry.delta.d, retained->delta.d);
        }
        if (authenticationclientEntryOwed(&entry))
            entries[owed++] = entry;
    }
    rwlockReadUnlock(&ts->users_lock);
    memoryFree(snapshot);
    qsort(entries, owed, sizeof(*entries), authenticationclientCompareEntries);
    memoryFree(ts->catchup_entries);
    ts->catchup_entries        = entries;
    ts->catchup_entries_count  = owed;
    ts->catchup_capture_needed = false;
    return true;
}

static bool authenticationclientCreateUsageBatch(tunnel_t *t)
{
    authenticationclient_tstate_t *ts       = tunnelGetState(t);
    user_accounting_snapshot_t    *snapshot = NULL;
    size_t                         total    = 0;
    rwlockReadLock(&ts->users_lock);
    if (! ts->users_loaded || ! usersSnapshotAccounting(ts->users, &snapshot, &total))
    {
        rwlockReadUnlock(&ts->users_lock);
        return false;
    }
    /* Fixed maximum geometry; ordinary allocation is fatal on heap OOM. */
    authenticationclient_accounting_entry_t *entries =
        memoryAllocate(kAuthenticationClientMaxBatchEntries * sizeof(*entries));
    cJSON     *root = cJSON_CreateObject(), *array = cJSON_CreateArray();
    discard cJSON_AddStringToObject(root, "epoch", ts->accounting_epoch);
    discard jsonAddUint64ToObject(root, "sequence", ts->next_batch_sequence);
    discard cJSON_AddItemToObject(root, "users", array);
    size_t     count        = 0;
    const bool catchup      = authenticationclientHasCatchup(ts);
    bool       more_entries = false;
    for (size_t i = 0; i < total; ++i)
    {
        const user_accounting_snapshot_t              *current = &snapshot[i];
        const authenticationclient_accounting_entry_t *owed    = NULL;
        if (catchup)
        {
            owed = authenticationclientCatchupEntry(ts, current->id);
            if (owed == NULL || ! authenticationclientEntryOwed(owed))
                continue;
        }
        user_ud_t delta = authenticationclientOwedTraffic(ts, current);
        if (owed != NULL)
        {
            /* A saturating aggregate rebase can hide A - B. Relative debt at
             * the cut remains known production until this batch's ACK. */
            delta.u = max(delta.u, owed->delta.u);
            delta.d = max(delta.d, owed->delta.d);
        }
        if (delta.u == 0 && delta.d == 0 && ! current->observation_pending)
            continue;
        /* Rebased/imported bytes are never observations. All local production
         * must pass through accounting with a valid installed clock. */
        assert(current->first_usage_at_ms != 0);
        if (count == kAuthenticationClientMaxBatchEntries)
        {
            more_entries = ! catchup;
            break;
        }
        entries[count++] = (authenticationclient_accounting_entry_t) {.id                = current->id,
                                                                      .totals            = current->traffic,
                                                                      .delta             = delta,
                                                                      .first_usage_at_ms = current->first_usage_at_ms};
        cJSON  *entry    = cJSON_CreateObject();
        discard jsonAddUint64ToObject(entry, "id", current->id);
        discard jsonAddUint64ToObject(entry, "up", delta.u);
        discard jsonAddUint64ToObject(entry, "down", delta.d);
        discard jsonAddUint64ToObject(entry, "first-usage-at-ms", current->first_usage_at_ms);
        discard cJSON_AddItemToArray(array, entry);
    }
    rwlockReadUnlock(&ts->users_lock);
    memoryFree(snapshot);
    if (more_entries)
    {
        mutexLock(&ts->control_mutex);
        ts->push_requested = true;
        mutexUnlock(&ts->control_mutex);
    }
    char *text = count != 0 ? cJSON_PrintUnformatted(root) : NULL;
    cJSON_Delete(root);
    if (text == NULL ||
        stringLength(text) > kAuthenticationClientMaxMessagePayload - kAuthenticationClientRequestHeaderSize)
    {
        cJSON_free(text);
        memoryFree(entries);
        return false;
    }
    /* Publish both immutable owners before any transport callback. */
    ts->pending_entries       = entries;
    ts->pending_entries_count = count;
    ts->pending_batch         = text;
    ts->pending_batch_length = (uint32_t) stringLength(text);
    return true;
}

bool authenticationclientSendPushUserStats(tunnel_t *t)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    mutexLock(&ts->control_mutex);
    ts->push_requested = true;
    const bool allowed = authenticationclientRequestMayBeSentLocked(ts, kAuthenticationClientRequestTypePushUserStats);
    if (allowed)
        ts->push_requested = false;
    mutexUnlock(&ts->control_mutex);
    if (! allowed)
        return false;
    if (ts->pending_batch == NULL && ! authenticationclientCreateUsageBatch(t))
    {
        authenticationclientScheduleSyncProgress(t);
        return false; /* Empty batch, or refusal: baseline and traffic stay intact. */
    }
    const bool sent = authenticationclientSendRequest(t,
                                                      kAuthenticationClientRequestTypePushUserStats,
                                                      (const uint8_t *) ts->pending_batch,
                                                      ts->pending_batch_length);
    if (! sent)
    {
        mutexLock(&ts->control_mutex);
        ts->push_requested = true;
        mutexUnlock(&ts->control_mutex);
        authenticationclientScheduleSyncProgress(t);
    }
    return sent;
}

void authenticationclientResumeSync(tunnel_t *t)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    mutexLock(&ts->control_mutex);
    const bool authenticated = ts->authenticated;
    const bool pull          = ts->pull_requested;
    const bool required_pull = ts->pull_required;
    const bool push          = ts->push_requested;
    mutexUnlock(&ts->control_mutex);
    if (! authenticated)
        discard authenticationclientSendAuthenticate(t);
    else if (ts->pending_batch != NULL)
        discard authenticationclientSendPushUserStats(t);
    else if (required_pull)
        discard authenticationclientSendGetAllUsers(t);
    else if (ts->catchup_capture_needed && ! authenticationclientCaptureCatchup(t))
        authenticationclientScheduleSyncProgress(t);
    else if (authenticationclientHasCatchup(ts))
    {
        discard authenticationclientSendPushUserStats(t);
        authenticationclientScheduleSyncProgress(t);
    }
    else
    {
        /* Ordinary pulls coalesce behind a waiting push. Every successful push
         * requires a refresh, so both jobs progress even when both stay due. */
        if (push && authenticationclientSendPushUserStats(t))
            return;
        /* An empty/refused batch must not swallow an already requested pull. */
        if (pull)
            discard authenticationclientSendGetAllUsers(t);
    }
    authenticationclientScheduleSyncProgress(t);
}

static bool authenticationclientAcknowledgeUsageBatch(tunnel_t *t, const uint8_t *data, uint32_t length)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    if (ts->pending_batch == NULL)
        return false;
    cJSON        *json   = cJSON_ParseWithLength((const char *) data, length);
    const cJSON  *epoch  = cJSON_GetObjectItemCaseSensitive(json, "epoch");
    const cJSON  *digest = cJSON_GetObjectItemCaseSensitive(json, "digest");
    const cJSON  *pull   = cJSON_GetObjectItemCaseSensitive(json, "needs-pull");
    uint64_t      sequence;
    uint8_t       decoded[32];
    sha256_hash_t expected;
    const bool    valid =
        cJSON_IsObject(json) && cJSON_IsString(epoch) && epoch->valuestring != NULL &&
        stringCompare(epoch->valuestring, ts->accounting_epoch) == 0 &&
        getUint64FromJson(&sequence, cJSON_GetObjectItemCaseSensitive(json, "sequence")) &&
        sequence == ts->next_batch_sequence && cJSON_IsString(digest) && digest->valuestring != NULL &&
        stringLength(digest->valuestring) == 64 &&
        asciiHexDecodeBytes((const uint8_t *) digest->valuestring, 64, decoded, sizeof(decoded)) &&
        wCryptoSHA256(&expected, (const uint8_t *) ts->pending_batch, ts->pending_batch_length) == kWCryptoOk &&
        memoryEqual(decoded, expected.bytes, sizeof(decoded)) && cJSON_IsTrue(pull);
    cJSON_Delete(json);
    if (! valid)
        return false;
    rwlockWriteLock(&ts->users_lock);
    for (size_t i = 0; i < ts->pending_entries_count; ++i)
    {
        const authenticationclient_accounting_entry_t *sent = &ts->pending_entries[i];
        user_t *base = usersLookupByIdentifier(ts->sync_baseline_users, sent->id);
        assert(base != NULL); /* Pull replacement is forbidden while unresolved. */
        rwlockWriteLock(&base->stats_lock);
        base->stats.traffic = sent->totals;
        rwlockWriteUnlock(&base->stats_lock);
        user_t *active = usersLookupByIdentifier(ts->users, sent->id);
        if (active != NULL)
            userAcknowledgeObservation(active, sent->first_usage_at_ms);
        authenticationclient_accounting_entry_t *owed = authenticationclientCatchupEntry(ts, sent->id);
        if (owed != NULL)
        {
            owed->delta.u = authenticationclientCounterDelta(owed->delta.u, sent->delta.u);
            owed->delta.d = authenticationclientCounterDelta(owed->delta.d, sent->delta.d);
            if (owed->first_usage_at_ms == sent->first_usage_at_ms)
                owed->first_usage_at_ms = 0;
        }
    }
    rwlockWriteUnlock(&ts->users_lock);
    memoryFree(ts->pending_entries);
    ts->pending_entries       = NULL;
    ts->pending_entries_count = 0;
    if (! authenticationclientHasCatchup(ts))
    {
        memoryFree(ts->catchup_entries);
        ts->catchup_entries       = NULL;
        ts->catchup_entries_count = 0;
    }
    cJSON_free(ts->pending_batch);
    ts->pending_batch        = NULL;
    ts->pending_batch_length = 0;
    mutexLock(&ts->control_mutex);
    if (ts->next_batch_sequence == UINT64_MAX)
        ts->continuity_error = true;
    else
        ++ts->next_batch_sequence;
    ts->pull_requested = true;
    ts->pull_required  = true;
    ts->last_ack_success_ms    = authenticationclientLocalTimeMS();
    ts->last_ack_success_valid = true;
    const bool exhausted       = ts->continuity_error;
    mutexUnlock(&ts->control_mutex);
    if (exhausted)
        authenticationclientRecordFailure(
            t, kAuthenticationClientFailureContinuity, kAuthenticationClientRequestTypePushUserStats);
    return true;
}

static bool authenticationclientApplyLocalTrafficDelta(users_t *dest, users_t *old_users, users_t *baseline_users);

static bool authenticationclientReplaceUsersFromJson(tunnel_t *t, const uint8_t *data, uint32_t data_len,
                                                     uint64_t config_revision, uint64_t stats_revision,
                                                     uint64_t revision_generation, uint64_t received_at_ms)
{
    authenticationclient_tstate_t *ts             = tunnelGetState(t);
    cJSON                         *json           = configLexicalParse((const char *) data, data_len, 8);
    uint64_t                       server_time_ms = 0, accounting_time_ms = 0;
    if (UNLIKELY(json == NULL))
    {
        LOGW("AuthenticationClient: GetAllUsers returned invalid JSON");
        return false;
    }
    if (UNLIKELY(
            ! getUint64FromJson(&server_time_ms, cJSON_GetObjectItemCaseSensitive(json, "server-time-ms")) ||
            ! getUint64FromJson(&accounting_time_ms, cJSON_GetObjectItemCaseSensitive(json, "accounting-time-ms")) ||
            accounting_time_ms == 0))
    {
        cJSON_Delete(json);
        LOGW("AuthenticationClient: GetAllUsers returned invalid server time metadata");
        return false;
    }

    /* Keep heap users_t allocations paired with memoryFreeAligned() on every cleanup path. */
    users_t *new_users = memoryAllocateAligned(sizeof(*new_users), 32);
    if (UNLIKELY(! usersCreate(new_users)))
    {
        cJSON_Delete(json);
        memoryFreeAligned(new_users);
        return false;
    }

    bool ok = usersFeedJson(new_users, json) && usersValidate(new_users) &&
              authenticationclientUsersHaveRequiredIds(new_users);
    cJSON_Delete(json);
    if (UNLIKELY(! ok))
    {
        usersDestroy(new_users);
        memoryFreeAligned(new_users);
        LOGW("AuthenticationClient: rejected invalid users table from server");
        return false;
    }

    users_t *new_baseline = authenticationclientCreateUsersCopy(new_users);
    if (UNLIKELY(new_baseline == NULL))
    {
        usersDestroy(new_users);
        memoryFreeAligned(new_users);
        return false;
    }

    users_t *old_baseline = NULL;
    rwlockWriteLock(&ts->users_lock);
    users_t *old_users = ts->users;
    // Runtime user tables are created at tunnel creation and stay non-NULL until destroy.
    if (UNLIKELY(! authenticationclientApplyLocalTrafficDelta(new_users, old_users, ts->sync_baseline_users)))
    {
        rwlockWriteUnlock(&ts->users_lock);
        authenticationclientDestroyUsers(new_baseline);
        usersDestroy(new_users);
        memoryFreeAligned(new_users);
        LOGW("AuthenticationClient: failed to preserve local traffic deltas during GetAllUsers replacement");
        return false;
    }
    if (UNLIKELY(! usersMigrateRuntimeStateByIdentifier(new_users, old_users)))
    {
        rwlockWriteUnlock(&ts->users_lock);
        authenticationclientDestroyUsers(new_baseline);
        usersDestroy(new_users);
        memoryFreeAligned(new_users);
        LOGW("AuthenticationClient: failed to preserve local runtime state during GetAllUsers replacement");
        return false;
    }
    authenticationclientInstallClientClocks(new_users, server_time_ms, accounting_time_ms, received_at_ms);
    usersResetFirstUsagePushRequests(new_users);

    ts->users               = new_users;
    old_baseline            = ts->sync_baseline_users;
    ts->sync_baseline_users = new_baseline;
    ts->users_generation += 1U;
    ts->local_config_revision     = config_revision;
    ts->local_stats_revision      = stats_revision;
    ts->local_revision_generation = revision_generation;
    ts->users_loaded              = true;
    ts->clock_loaded              = true;
    rwlockWriteUnlock(&ts->users_lock);

    mutexLock(&ts->control_mutex);
    ts->first_usage_push_requested = false;
    ts->first_usage_push_deferred  = false;
    ts->pull_required              = false;
    ts->last_pull_success_ms       = authenticationclientLocalTimeMS();
    ts->last_pull_success_valid    = true;
    mutexUnlock(&ts->control_mutex);

    usersDestroy(old_users);
    memoryFreeAligned(old_users);
    authenticationclientDestroyUsers(old_baseline);

    if (ts->catchup_capture_needed)
        discard authenticationclientCaptureCatchup(t); /* Failure retains the obligation for the progress timer. */

    if (ts->verbose)
    {
        LOGD("AuthenticationClient: installed pulled users table users=%zu config-revision=%" PRIu64
             " stats-revision=%" PRIu64 " local-generation=%" PRIu64,
             usersCount(new_users),
             config_revision,
             stats_revision,
             revision_generation);
    }

    LOGI("AuthenticationClient: pulled %zu users from server", usersCount(new_users));
    return true;
}

static bool authenticationclientApplyLocalTrafficDelta(users_t *dest, users_t *old_users, users_t *baseline_users)
{
    // Internal helper: current caller passes initialized user tables.
    const size_t users_count = usersCount(old_users);
    for (size_t i = 0; i < users_count; ++i)
    {
        user_t *old_user = usersGetAt(old_users, i);
        if (UNLIKELY(old_user == NULL || old_user->id == 0))
        {
            continue;
        }

        user_stat_t old_stats = {0};
        userGetStats(old_user, &old_stats);

        user_stat_t baseline_stats = {0};
        if (baseline_users != NULL)
        {
            user_t *baseline_user = authenticationclientLookupUserByStableId(baseline_users, old_user);
            if (baseline_user != NULL)
            {
                userGetStats(baseline_user, &baseline_stats);
            }
        }

        const uint64_t upload_delta   = authenticationclientCounterDelta(old_stats.traffic.u, baseline_stats.traffic.u);
        const uint64_t download_delta = authenticationclientCounterDelta(old_stats.traffic.d, baseline_stats.traffic.d);
        if (LIKELY(upload_delta == 0 && download_delta == 0))
        {
            continue;
        }

        users_update_result_t result =
            authenticationclientAddTrafficByStableId(dest, old_user, upload_delta, download_delta);
        if (UNLIKELY(result != kUsersUpdateResultOk && result != kUsersUpdateResultUserNotFound))
        {
            return false;
        }
    }

    return true;
}

static void authenticationclientHandleError(tunnel_t *t, line_t *l, uint8_t request_type, const uint8_t *data,
                                            uint32_t length)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    const bool                     continuity =
        length == sizeof("accounting-continuity-lost") - 1 && memoryEqual(data, "accounting-continuity-lost", length);
    const bool credential_rejected = request_type == kAuthenticationClientRequestTypeAuthenticate &&
                                     length == sizeof("authentication-failed") - 1 &&
                                     memoryEqual(data, "authentication-failed", length);
    if (credential_rejected)
    {
        mutexLock(&ts->control_mutex);
        ts->auth_rejected = true;
        mutexUnlock(&ts->control_mutex);
    }
    const bool authentication =
        length == sizeof("authentication-required") - 1 && memoryEqual(data, "authentication-required", length);
    authenticationclientRecordFailure(t,
                                      continuity            ? kAuthenticationClientFailureContinuity
                                      : credential_rejected ? kAuthenticationClientFailureCredentialRejected
                                                            : kAuthenticationClientFailureRemoteError,
                                      request_type);
    LOGW("AuthenticationClient: request %u failed: %.*s", request_type, (int) min(length, 128U), (const char *) data);
    if ((continuity || request_type == kAuthenticationClientRequestTypePushUserStats) && ! authentication)
    {
        mutexLock(&ts->control_mutex);
        if (ts->pending_batch != NULL)
            ts->continuity_error = true;
        else if (continuity)
        {
            memoryZero(ts->accounting_epoch, sizeof(ts->accounting_epoch));
            ts->next_batch_sequence = 1;
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
    authenticationclientRecoverControlLine(t, l, true);
}

static void authenticationclientHandleResponseFrame(tunnel_t *t, line_t *l, uint8_t response_type,
                                                    uint32_t correlation_id, const uint8_t *data, uint32_t data_len,
                                                    uint64_t config_revision, uint64_t stats_revision,
                                                    uint64_t received_at_ms)
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
    authenticationclientUpdateRequestTimer(t);
    if (! found)
        return; /* A stale correlation cannot enroll or settle accounting. */
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
        }
        memoryCopy(ts->token, data, 64);
        ts->authenticated  = true;
        ts->auth_rejected          = false;
        ts->catchup_capture_needed = true;
        ts->pull_requested = true;
        ts->pull_required  = true;
        ts->last_auth_success_ms    = authenticationclientLocalTimeMS();
        ts->last_auth_success_valid = true;
        mutexUnlock(&ts->control_mutex);
        authenticationclientResumeSync(t);
        return;
    }
    case kAuthenticationClientRequestTypeGetAllUsers:
        if (response_type != kAuthenticationClientResponseTypeUsers || ts->pending_batch != NULL ||
            ! authenticationclientReplaceUsersFromJson(
                t, data, data_len, config_revision, stats_revision, generation, received_at_ms))
        {
            authenticationclientRecordFailure(t, kAuthenticationClientFailureInvalidResponse, request_type);
            authenticationclientRecoverControlLine(t, l, true);
            return;
        }
        break;
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
    if (ts->catchup_capture_needed || authenticationclientHasCatchup(ts))
        authenticationclientScheduleSyncProgress(t);
    else
        authenticationclientResumeSync(t);
}

static bool authenticationclientReadMessageHeader(authenticationclient_lstate_t *ls, uint32_t *message_body_len)
{
    uint8_t header[kAuthenticationClientMessageHeaderSize];

    if (bufferstreamGetBufLen(&ls->read_stream) < kAuthenticationClientMessageHeaderSize)
    {
        return false;
    }

    bufferstreamViewBytesAt(&ls->read_stream, 0, header, sizeof(header));
    *message_body_len = authenticationclientReadNetworkUI32(header);
    return true;
}

static bool authenticationclientValidateResponsePayload(sbuf_t *payload)
{
    const uint8_t *ptr       = sbufGetRawPtr(payload);
    uint32_t       remaining = sbufGetLength(payload);
    uint32_t       offset    = 0;

    while (remaining > 0)
    {
        if (UNLIKELY(remaining < kAuthenticationClientResponseHeaderSize))
        {
            LOGW("AuthenticationClient: response frame has trailing bytes smaller than a frame header");
            return false;
        }

        const uint8_t *frame = ptr + offset;
        const uint32_t response_data_len =
            authenticationclientReadNetworkUI32(frame + 1 + kAuthenticationClientCorrelationIdSize);
        if (UNLIKELY(response_data_len > kAuthenticationClientMaxResponsePayload))
        {
            LOGW("AuthenticationClient: response frame is oversized");
            return false;
        }
        if (UNLIKELY(response_data_len > remaining - kAuthenticationClientResponseHeaderSize))
        {
            LOGW("AuthenticationClient: response frame is incomplete");
            return false;
        }

        const uint32_t consumed = kAuthenticationClientResponseHeaderSize + response_data_len;
        offset += consumed;
        remaining -= consumed;
    }

    return true;
}

bool authenticationclientProcessResponses(tunnel_t *t, line_t *l, authenticationclient_lstate_t *ls)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);
    if (ls->processing_responses)
        return true;
    ls->processing_responses = true;

    while (true)
    {
        uint32_t message_body_len = 0;
        if (! authenticationclientReadMessageHeader(ls, &message_body_len))
        {
            ls->processing_responses = false;
            return true;
        }

        if (UNLIKELY(message_body_len < kAuthenticationClientRevisionHeaderSize))
        {
            authenticationclientRecordFailure(t, kAuthenticationClientFailureInvalidResponse, 0);
            authenticationclientRecoverControlLine(t, l, true);
            return false;
        }
        if (UNLIKELY(message_body_len >
                     kAuthenticationClientMaxResponsePayload + kAuthenticationClientRevisionHeaderSize))
        {
            authenticationclientRecordFailure(t, kAuthenticationClientFailureInvalidResponse, 0);
            authenticationclientRecoverControlLine(t, l, true);
            return false;
        }

        const size_t message_len = (size_t) kAuthenticationClientMessageHeaderSize + (size_t) message_body_len;
        if (bufferstreamGetBufLen(&ls->read_stream) < message_len)
        {
            ls->processing_responses = false;
            return true;
        }

        /* Include framing/JSON construction and subsequent lock waits in the
         * receipt-to-install elapsed time, including a maximum-sized pull. */
        const uint64_t received_at_ms = authenticationclientLocalTimeMS();
        sbuf_t        *payload        = authenticationStreamReadExact(&ls->read_stream, (uint32_t) message_len);
        sbufShiftRight(payload, kAuthenticationClientMessageHeaderSize);

        const uint8_t *revision_ptr    = sbufGetRawPtr(payload);
        const uint64_t config_revision = authenticationclientReadNetworkUI64(revision_ptr);
        const uint64_t stats_revision  = authenticationclientReadNetworkUI64(revision_ptr + sizeof(uint64_t));
        sbufShiftRight(payload, kAuthenticationClientRevisionHeaderSize);

        if (UNLIKELY(! authenticationclientValidateResponsePayload(payload)))
        {
            lineReuseBuffer(l, payload);
            authenticationclientRecordFailure(t, kAuthenticationClientFailureInvalidResponse, 0);
            authenticationclientRecoverControlLine(t, l, true);
            return false;
        }

        if (ts->verbose)
        {
            LOGD("AuthenticationClient: processing response message body=%u frame-payload=%u config-revision=%" PRIu64
                 " stats-revision=%" PRIu64,
                 (unsigned int) message_body_len,
                 (unsigned int) sbufGetLength(payload),
                 config_revision,
                 stats_revision);
        }

        const uint8_t *ptr       = sbufGetRawPtr(payload);
        uint32_t       remaining = sbufGetLength(payload);
        uint32_t       offset    = 0;
        while (remaining > 0)
        {
            const uint8_t *frame          = ptr + offset;
            const uint8_t  response_type  = frame[0];
            const uint32_t correlation_id = authenticationclientCorrelationIdRead(frame + 1);
            const uint32_t response_data_len =
                authenticationclientReadNetworkUI32(frame + 1 + kAuthenticationClientCorrelationIdSize);
            const uint8_t *response_data = frame + kAuthenticationClientResponseHeaderSize;

            authenticationclientHandleResponseFrame(t,
                                                    l,
                                                    response_type,
                                                    correlation_id,
                                                    response_data,
                                                    response_data_len,
                                                    config_revision,
                                                    stats_revision,
                                                    received_at_ms);

            const uint32_t consumed = kAuthenticationClientResponseHeaderSize + response_data_len;
            offset += consumed;
            remaining -= consumed;

            if (UNLIKELY(! lineIsAlive(l)))
            {
                lineReuseBuffer(l, payload);
                return false;
            }
        }

        lineReuseBuffer(l, payload);
    }
}

void authenticationclientOpenControlLine(tunnel_t *t)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);

    // The control line is structurally owned by worker 0; an unregistered or
    // lwIP caller must never reach here (it queues in
    // authenticationclientScheduleReconnect() instead).
    if (UNLIKELY(! currentThreadIsEventWorkerWID(0)))
    {
        LOGF("AuthenticationClient: control line must be opened on worker 0, caller worker: %d",
             workerWIDForLog(getWID()));
        abortProgramNow(1);
        return;
    }

    mutexLock(&ts->control_mutex);
    if (UNLIKELY(! ts->started || ts->stopping || ts->continuity_error || ts->control_line != NULL))
    {
        if (ts->verbose)
        {
            LOGD("AuthenticationClient: skipped opening control line stopping=%s existing-line=%s",
                 boolToTrueFalse(ts->stopping),
                 boolToTrueFalse(ts->control_line != NULL));
        }
        mutexUnlock(&ts->control_mutex);
        return;
    }
    authenticationclientClearSessionLocked(ts);
    ts->connected     = false;
    ts->write_paused  = false;
    ts->pending_count = 0;
    mutexUnlock(&ts->control_mutex);
    authenticationclientResetFirstUsagePushRuntime(t);

    line_t                        *line = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), 0);
    authenticationclient_lstate_t *ls   = lineGetState(line, t);
    authenticationclientLinestateInitialize(ls, lineGetBufferPool(line));

    if (ts->verbose)
    {
        LOGD("AuthenticationClient: opening control line on worker %u", (unsigned int) lineGetWID(line));
    }

    mutexLock(&ts->control_mutex);
    ts->control_line = line;
    mutexUnlock(&ts->control_mutex);

    if (UNLIKELY(! lineCallWithRef(line, tunnelNextUpStreamInit, t)))
    {
        if (ts->verbose)
        {
            LOGD("AuthenticationClient: control line closed during upstream Init");
        }
        return;
    }
}

void authenticationclientCloseControlLine(tunnel_t *t, line_t *l, bool propagate_finish)
{
    authenticationclient_tstate_t *ts      = tunnelGetState(t);
    const bool                     verbose = ts->verbose;

    mutexLock(&ts->control_mutex);
    if (LIKELY(ts->control_line == l))
    {
        ts->control_line = NULL;
    }
    ts->connected     = false;
    ts->write_paused  = false;
    ts->pending_count = 0;
    authenticationclientClearSessionLocked(ts);
    mutexUnlock(&ts->control_mutex);
    /* Retain unacknowledged relative debt; a saturated A - B cannot rebuild it. */
    ts->catchup_capture_needed = true;
    authenticationclientUpdateRequestTimer(t);
    authenticationclientResetFirstUsagePushRuntime(t);

    if (verbose)
    {
        LOGD("AuthenticationClient: closing control line propagate-finish=%s", boolToTrueFalse(propagate_finish));
    }

    authenticationclient_lstate_t *ls = lineGetState(l, t);
    authenticationclientLinestateDestroy(ls);

    // This tunnel owns the control line; upstream Finish is non-reentrant, then we destroy it locally.
    if (propagate_finish)
    {
        tunnelNextUpStreamFinish(t, l);
    }

    lineDestroy(l);
}

void authenticationclientPingTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (UNLIKELY(t == NULL))
    {
        return;
    }

    authenticationclient_tstate_t *ts            = tunnelGetState(t);
    bool                           authenticated = false;
    bool                           connected     = false;

    if (UNLIKELY(authenticationclientCloseTimedOutControlLine(t)))
    {
        return;
    }

    mutexLock(&ts->control_mutex);
    connected     = ts->connected;
    authenticated = ts->authenticated;
    mutexUnlock(&ts->control_mutex);

    if (ts->verbose)
    {
        LOGD("AuthenticationClient: ping timer tick connected=%s authenticated=%s",
             boolToTrueFalse(connected),
             boolToTrueFalse(authenticated));
    }

    if (UNLIKELY(! connected))
    {
        authenticationclientScheduleReconnect(t);
        return;
    }
    if (authenticated)
    {
        discard authenticationclientSendPing(t);
    }
    else
    {
        discard authenticationclientSendAuthenticate(t);
    }
}

static uint32_t authenticationclientSmallestNonZero(uint32_t a, uint32_t b)
{
    if (a == 0)
    {
        return b;
    }
    if (b == 0 || a < b)
    {
        return a;
    }
    return b;
}

static uint32_t authenticationclientSyncInterval(authenticationclient_tstate_t *ts)
{
    return authenticationclientSmallestNonZero(ts->pull_interval_ms, ts->push_interval_ms);
}

static bool authenticationclientSyncJobDue(uint32_t now_ms, uint32_t *last_attempt_ms, uint32_t interval_ms)
{
    if (interval_ms == 0)
    {
        return false;
    }
    if ((uint32_t) (now_ms - *last_attempt_ms) < interval_ms)
    {
        return false;
    }

    *last_attempt_ms = now_ms;
    return true;
}

static bool authenticationclientUsersLoaded(tunnel_t *t)
{
    authenticationclient_tstate_t *ts           = tunnelGetState(t);
    bool                           users_loaded = false;

    rwlockReadLock(&ts->users_lock);
    users_loaded = ts->users_loaded;
    rwlockReadUnlock(&ts->users_lock);

    return users_loaded;
}

/*
 * Category B (orderly runtime failure). Called from the worker-0 startup task,
 * which is a runtime worker context: the sync timer is required whenever a sync
 * interval is configured, so a failed allocation ends the process. The caller
 * must stop its startup sequence when this returns false.
 */
bool authenticationclientStartSyncTimer(tunnel_t *t)
{
    authenticationclient_tstate_t *ts               = tunnelGetState(t);
    const uint32_t                 sync_interval_ms = authenticationclientSyncInterval(ts);

    if (sync_interval_ms == 0 || ts->sync_timer != NULL)
    {
        return true;
    }

    const uint32_t now_ms = getTickMS();
    ts->last_pull_sync_ms = now_ms;
    ts->last_push_sync_ms = now_ms;

    ts->sync_timer = wtimerAdd(getWorkerLoop(0), authenticationclientSyncTimerCallback, sync_interval_ms, INFINITE);
    if (UNLIKELY(ts->sync_timer == NULL))
    {
        LOGF("AuthenticationClient: failed to create sync timer");
        if (! requestProgramShutdown(1))
        {
            abortProgramNow(1);
        }
        return false;
    }
    weventSetUserData(ts->sync_timer, t);

    if (ts->verbose)
    {
        LOGD("AuthenticationClient: sync timer enabled every %u ms", (unsigned int) sync_interval_ms);
    }

    return true;
}

void authenticationclientSyncTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (UNLIKELY(t == NULL))
    {
        return;
    }

    authenticationclient_tstate_t *ts = tunnelGetState(t);

    if (UNLIKELY(authenticationclientCloseTimedOutControlLine(t)))
    {
        return;
    }

    const uint32_t now_ms   = getTickMS();
    const bool     push_due = authenticationclientSyncJobDue(now_ms, &ts->last_push_sync_ms, ts->push_interval_ms);
    const bool     pull_due = authenticationclientSyncJobDue(now_ms, &ts->last_pull_sync_ms, ts->pull_interval_ms);

    if (ts->verbose)
    {
        LOGD("AuthenticationClient: sync timer tick push-due=%s pull-due=%s",
             boolToTrueFalse(push_due),
             boolToTrueFalse(pull_due));
    }

    if (push_due)
    {
        discard authenticationclientSendPushUserStats(t);
    }

    if (ts->pull_interval_ms == 0 && authenticationclientUsersLoaded(t))
    {
        return;
    }

    const bool should_pull = authenticationclientShouldSendGetAllUsers(t, pull_due);
    if (ts->verbose)
    {
        LOGD("AuthenticationClient: sync timer pull decision send=%s", boolToTrueFalse(should_pull));
    }

    if (! should_pull)
    {
        return;
    }

    ts->last_pull_sync_ms = now_ms;
    discard authenticationclientSendGetAllUsers(t);
}
