#include "structure.h"

#include "loggers/network_logger.h"

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
    memoryFree(users);
}

static users_t *authenticationclientCreateUsersCopy(const users_t *src)
{
    if (UNLIKELY(src == NULL))
    {
        return NULL;
    }

    cJSON *json = usersToJson(src);
    if (UNLIKELY(json == NULL))
    {
        return NULL;
    }

    users_t *copy = memoryAllocate(sizeof(*copy));
    if (UNLIKELY(copy == NULL || ! usersCreate(copy)))
    {
        cJSON_Delete(json);
        memoryFree(copy);
        return NULL;
    }

    bool ok = usersFeedJson(copy, json) && usersValidate(copy);
    cJSON_Delete(json);
    if (UNLIKELY(! ok))
    {
        authenticationclientDestroyUsers(copy);
        return NULL;
    }

    return copy;
}

static uint64_t authenticationclientCounterDelta(uint64_t current, uint64_t baseline)
{
    return current > baseline ? current - baseline : 0;
}

static void authenticationclientClearSessionLocked(authenticationclient_tstate_t *ts)
{
    users_t *pending_push_users = NULL;
    rwlockWriteLock(&ts->users_lock);
    pending_push_users     = ts->pending_push_users;
    ts->pending_push_users = NULL;
    rwlockWriteUnlock(&ts->users_lock);

    wCryptoZero(ts->token, sizeof(ts->token));
    ts->authenticated  = false;
    ts->auth_in_flight = false;
    ts->pull_in_flight = false;
    ts->push_in_flight = false;

    authenticationclientDestroyUsers(pending_push_users);
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

    authenticationclient_pending_request_t *new_items =
        memoryReAllocate(ts->pending_requests, sizeof(*new_items) * (size_t) new_capacity);
    if (UNLIKELY(new_items == NULL))
    {
        return false;
    }

    ts->pending_requests = new_items;
    ts->pending_capacity = new_capacity;
    return true;
}

static bool authenticationclientPendingAppend(authenticationclient_tstate_t *ts, uint32_t correlation_id,
                                              uint8_t request_type, uint32_t created_at_ms)
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

static bool authenticationclientPendingFindTimedOutLocked(authenticationclient_tstate_t *ts, uint32_t now_ms,
                                                          authenticationclient_pending_request_t *pending_out)
{
    if (UNLIKELY(ts->request_timeout_ms == 0))
    {
        return false;
    }

    for (uint32_t i = 0; i < ts->pending_count; ++i)
    {
        const authenticationclient_pending_request_t *pending = &ts->pending_requests[i];
        if (UNLIKELY((uint32_t) (now_ms - pending->created_at_ms) >= ts->request_timeout_ms))
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
    if (UNLIKELY(ts->stopping || ! ts->connected || ts->write_paused || ts->control_line == NULL))
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
        return ! ts->pull_in_flight;
    }
    if (request_type == kAuthenticationClientRequestTypePushUserStats)
    {
        return ! ts->push_in_flight;
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
}

static sbuf_t *authenticationclientCreateRequestMessage(line_t *l, uint8_t request_type, uint32_t correlation_id,
                                                        const uint8_t *request_data, uint32_t request_data_len,
                                                        const uint8_t token[kAuthenticationClientSessionTokenSize])
{
    const uint32_t frame_len   = kAuthenticationClientRequestHeaderSize + request_data_len;
    const uint32_t message_len = kAuthenticationClientRequestEnvelopeHeaderSize + frame_len;

    if (UNLIKELY(request_data_len > kAuthenticationClientMaxRequestData ||
                 frame_len > kAuthenticationClientMaxMessagePayload || message_len < frame_len))
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

static void authenticationclientStorePendingPushUsers(tunnel_t *t, users_t **snapshot)
{
    if (UNLIKELY(snapshot == NULL || *snapshot == NULL))
    {
        return;
    }

    authenticationclient_tstate_t *ts           = tunnelGetState(t);
    users_t                       *old_snapshot = NULL;

    rwlockWriteLock(&ts->users_lock);
    old_snapshot           = ts->pending_push_users;
    ts->pending_push_users = *snapshot;
    *snapshot              = NULL;
    rwlockWriteUnlock(&ts->users_lock);

    authenticationclientDestroyUsers(old_snapshot);
}

static void authenticationclientClearPendingPushUsers(tunnel_t *t)
{
    authenticationclient_tstate_t *ts                 = tunnelGetState(t);
    users_t                       *pending_push_users = NULL;

    rwlockWriteLock(&ts->users_lock);
    pending_push_users     = ts->pending_push_users;
    ts->pending_push_users = NULL;
    rwlockWriteUnlock(&ts->users_lock);

    authenticationclientDestroyUsers(pending_push_users);
}

static void authenticationclientAcknowledgePendingPushUsers(tunnel_t *t, bool revisions_current,
                                                            uint64_t config_revision, uint64_t stats_revision,
                                                            uint64_t revision_generation)
{
    authenticationclient_tstate_t *ts           = tunnelGetState(t);
    users_t                       *old_baseline = NULL;

    rwlockWriteLock(&ts->users_lock);
    if (LIKELY(ts->pending_push_users != NULL))
    {
        old_baseline            = ts->sync_baseline_users;
        ts->sync_baseline_users = ts->pending_push_users;
        ts->pending_push_users  = NULL;
        if (revisions_current)
        {
            ts->local_config_revision     = config_revision;
            ts->local_stats_revision      = stats_revision;
            ts->local_revision_generation = revision_generation;
        }
    }
    rwlockWriteUnlock(&ts->users_lock);

    authenticationclientDestroyUsers(old_baseline);
}

static bool authenticationclientSendRequestWithSnapshot(tunnel_t *t, uint8_t request_type, const uint8_t *request_data,
                                                        uint32_t request_data_len, users_t *push_snapshot)
{
    authenticationclient_tstate_t *ts                                           = tunnelGetState(t);
    uint8_t                        token[kAuthenticationClientSessionTokenSize] = {0};
    uint32_t                       correlation_id                               = 0;
    uint32_t                       now_ms                                       = getTickMS();

    line_t *line = NULL;

    mutexLock(&ts->control_mutex);
    if (UNLIKELY(! authenticationclientRequestMayBeSentLocked(ts, request_type)))
    {
        mutexUnlock(&ts->control_mutex);
        authenticationclientDestroyUsers(push_snapshot);
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
        authenticationclientDestroyUsers(push_snapshot);
        return false;
    }
    authenticationclientMarkRequestInFlightLocked(ts, request_type, true);

    if (request_type == kAuthenticationClientRequestTypePushUserStats)
    {
        authenticationclientStorePendingPushUsers(t, &push_snapshot);
    }

    if (request_type != kAuthenticationClientRequestTypeAuthenticate)
    {
        memoryCopy(token, ts->token, sizeof(token));
    }

    if (LIKELY(ts->control_line != NULL && lineIsAlive(ts->control_line)))
    {
        line = ts->control_line;
        lineLock(line);
    }
    mutexUnlock(&ts->control_mutex);

    if (UNLIKELY(line == NULL))
    {
        authenticationclientRemovePendingById(t, correlation_id);
        if (request_type == kAuthenticationClientRequestTypePushUserStats)
        {
            authenticationclientClearPendingPushUsers(t);
        }
        authenticationclientDestroyUsers(push_snapshot);
        return false;
    }

    sbuf_t *message = authenticationclientCreateRequestMessage(
        line, request_type, correlation_id, request_data, request_data_len, token);
    if (UNLIKELY(message == NULL))
    {
        authenticationclientRemovePendingById(t, correlation_id);
        if (request_type == kAuthenticationClientRequestTypePushUserStats)
        {
            authenticationclientClearPendingPushUsers(t);
        }
        authenticationclientDestroyUsers(push_snapshot);
        lineUnlock(line);
        return false;
    }

    tunnelNextUpStreamPayload(t, line, message);
    bool alive = lineIsAlive(line);
    authenticationclientDestroyUsers(push_snapshot);
    lineUnlock(line);
    return alive;
}

static bool authenticationclientSendRequest(tunnel_t *t, uint8_t request_type, const uint8_t *request_data,
                                            uint32_t request_data_len)
{
    return authenticationclientSendRequestWithSnapshot(t, request_type, request_data, request_data_len, NULL);
}

static bool authenticationclientCloseTimedOutControlLine(tunnel_t *t)
{
    authenticationclient_tstate_t         *ts      = tunnelGetState(t);
    authenticationclient_pending_request_t pending = {0};
    line_t                                *line    = NULL;
    const uint32_t                         now_ms  = getTickMS();

    mutexLock(&ts->control_mutex);
    if (UNLIKELY(ts->control_line != NULL && lineIsAlive(ts->control_line) &&
                 authenticationclientPendingFindTimedOutLocked(ts, now_ms, &pending)))
    {
        line = ts->control_line;
        lineLock(line);
    }
    mutexUnlock(&ts->control_mutex);

    if (LIKELY(line == NULL))
    {
        return false;
    }

    LOGW("AuthenticationClient: request type %u with correlation id %u timed out after %u ms; reconnecting",
         (unsigned int) pending.request_type,
         (unsigned int) pending.correlation_id,
         (unsigned int) (now_ms - pending.created_at_ms));

    authenticationclientCloseControlLine(t, line, true);
    lineUnlock(line);
    authenticationclientScheduleReconnect(t);
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

    rwlockReadLock(&ts->users_lock);
    local_config_revision     = ts->local_config_revision;
    local_stats_revision      = ts->local_stats_revision;
    local_revision_generation = ts->local_revision_generation;
    rwlockReadUnlock(&ts->users_lock);

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
    if (UNLIKELY(json == NULL))
    {
        return false;
    }
    if (UNLIKELY(! cJSON_AddStringToObject(json, "name", ts->name) ||
                 ! cJSON_AddStringToObject(json, "secret", ts->secret)))
    {
        cJSON_Delete(json);
        return false;
    }

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
    return authenticationclientSendRequest(t, kAuthenticationClientRequestTypeGetAllUsers, NULL, 0);
}

static bool authenticationclientJsonAddUint64(cJSON *json_obj, const char *key, uint64_t value)
{
    static const uint64_t json_safe_integer_max = 9007199254740991ULL;
    char                  number_buf[32];

    if (value <= json_safe_integer_max)
    {
        return cJSON_AddNumberToObject(json_obj, key, (double) value) != NULL;
    }

    snprintf(number_buf, sizeof(number_buf), "%" PRIu64, value);
    return cJSON_AddStringToObject(json_obj, key, number_buf) != NULL;
}

static bool authenticationclientAppendStatsHint(cJSON *array, user_t *user, const users_t *baseline_users)
{
    if (user == NULL || user->password == NULL || user->password[0] == '\0' || ! user->sha256_pass_valid)
    {
        return true;
    }

    user_stat_t stats = {0};
    userGetStats(user, &stats);

    user_stat_t baseline_stats = {0};
    if (baseline_users != NULL)
    {
        user_t *baseline_user = usersLookupBySHA256((users_t *) baseline_users, user->sha256_pass.bytes);
        if (baseline_user != NULL)
        {
            userGetStats(baseline_user, &baseline_stats);
        }
    }

    const uint64_t upload_delta   = authenticationclientCounterDelta(stats.traffic.u, baseline_stats.traffic.u);
    const uint64_t download_delta = authenticationclientCounterDelta(stats.traffic.d, baseline_stats.traffic.d);
    if (upload_delta == 0 && download_delta == 0)
    {
        return true;
    }

    cJSON *hint         = cJSON_CreateObject();
    cJSON *hint_stats   = cJSON_CreateObject();
    cJSON *hint_traffic = cJSON_CreateObject();
    if (UNLIKELY(hint == NULL || hint_stats == NULL || hint_traffic == NULL))
    {
        cJSON_Delete(hint);
        cJSON_Delete(hint_stats);
        cJSON_Delete(hint_traffic);
        return false;
    }

    if (UNLIKELY(! cJSON_AddStringToObject(hint, "password", user->password)))
    {
        cJSON_Delete(hint);
        cJSON_Delete(hint_stats);
        cJSON_Delete(hint_traffic);
        return false;
    }
    if (upload_delta > 0)
    {
        if (UNLIKELY(! authenticationclientJsonAddUint64(hint_traffic, "up", stats.traffic.u)))
        {
            cJSON_Delete(hint);
            cJSON_Delete(hint_stats);
            cJSON_Delete(hint_traffic);
            return false;
        }
    }
    if (download_delta > 0)
    {
        if (UNLIKELY(! authenticationclientJsonAddUint64(hint_traffic, "down", stats.traffic.d)))
        {
            cJSON_Delete(hint);
            cJSON_Delete(hint_stats);
            cJSON_Delete(hint_traffic);
            return false;
        }
    }
    if (UNLIKELY(! cJSON_AddItemToObject(hint_stats, "traffic", hint_traffic)))
    {
        cJSON_Delete(hint);
        cJSON_Delete(hint_stats);
        cJSON_Delete(hint_traffic);
        return false;
    }
    hint_traffic = NULL;
    if (UNLIKELY(! cJSON_AddItemToObject(hint, "stats", hint_stats)))
    {
        cJSON_Delete(hint);
        cJSON_Delete(hint_stats);
        return false;
    }
    hint_stats = NULL;
    if (UNLIKELY(! cJSON_AddItemToArray(array, hint)))
    {
        cJSON_Delete(hint);
        return false;
    }

    return true;
}

static bool authenticationclientTakeUsersSnapshots(tunnel_t *t, users_t **snapshot_out, users_t **baseline_out)
{
    authenticationclient_tstate_t *ts       = tunnelGetState(t);
    users_t                       *snapshot = NULL;
    users_t                       *baseline = NULL;

    rwlockReadLock(&ts->users_lock);
    if (LIKELY(ts->users != NULL))
    {
        snapshot = authenticationclientCreateUsersCopy(ts->users);
    }
    if (snapshot != NULL && ts->sync_baseline_users != NULL)
    {
        baseline = authenticationclientCreateUsersCopy(ts->sync_baseline_users);
        if (UNLIKELY(baseline == NULL))
        {
            authenticationclientDestroyUsers(snapshot);
            snapshot = NULL;
        }
    }
    rwlockReadUnlock(&ts->users_lock);

    if (UNLIKELY(snapshot == NULL))
    {
        return false;
    }

    *snapshot_out = snapshot;
    *baseline_out = baseline;
    return true;
}

static cJSON *authenticationclientBuildStatsHintsJson(users_t *snapshot, const users_t *baseline)
{
    if (UNLIKELY(snapshot == NULL))
    {
        return NULL;
    }

    cJSON *root  = cJSON_CreateObject();
    cJSON *array = cJSON_CreateArray();
    if (UNLIKELY(root == NULL || array == NULL || ! cJSON_AddItemToObject(root, "users", array)))
    {
        cJSON_Delete(root);
        cJSON_Delete(array);
        return NULL;
    }

    const size_t users_count = usersCount(snapshot);
    for (size_t i = 0; i < users_count; ++i)
    {
        user_t *user = usersGetAt(snapshot, i);
        if (UNLIKELY(! authenticationclientAppendStatsHint(array, user, baseline)))
        {
            cJSON_Delete(root);
            return NULL;
        }
    }

    return root;
}

bool authenticationclientSendPushUserStats(tunnel_t *t)
{
    users_t *snapshot = NULL;
    users_t *baseline = NULL;
    if (UNLIKELY(! authenticationclientTakeUsersSnapshots(t, &snapshot, &baseline)))
    {
        return false;
    }

    cJSON *json = authenticationclientBuildStatsHintsJson(snapshot, baseline);
    authenticationclientDestroyUsers(baseline);
    if (UNLIKELY(json == NULL))
    {
        authenticationclientDestroyUsers(snapshot);
        return false;
    }

    char *text = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (UNLIKELY(text == NULL))
    {
        authenticationclientDestroyUsers(snapshot);
        return false;
    }

    bool ok = authenticationclientSendRequestWithSnapshot(t,
                                                          kAuthenticationClientRequestTypePushUserStats,
                                                          (const uint8_t *) text,
                                                          (uint32_t) stringLength(text),
                                                          snapshot);
    cJSON_free(text);
    return ok;
}

static bool authenticationclientApplyLocalTrafficDelta(users_t *dest, users_t *old_users, users_t *baseline_users);

static bool authenticationclientReplaceUsersFromJson(tunnel_t *t, const uint8_t *data, uint32_t data_len,
                                                     uint64_t config_revision, uint64_t stats_revision,
                                                     uint64_t revision_generation)
{
    authenticationclient_tstate_t *ts   = tunnelGetState(t);
    cJSON                         *json = cJSON_ParseWithLength((const char *) data, data_len);
    if (UNLIKELY(json == NULL))
    {
        LOGW("AuthenticationClient: GetAllUsers returned invalid JSON");
        return false;
    }

    users_t *new_users = memoryAllocate(sizeof(*new_users));
    if (UNLIKELY(new_users == NULL || ! usersCreate(new_users)))
    {
        cJSON_Delete(json);
        memoryFree(new_users);
        return false;
    }

    bool ok = usersFeedJson(new_users, json) && usersValidate(new_users);
    cJSON_Delete(json);
    if (UNLIKELY(! ok))
    {
        usersDestroy(new_users);
        memoryFree(new_users);
        LOGW("AuthenticationClient: rejected invalid users table from server");
        return false;
    }

    users_t *new_baseline = authenticationclientCreateUsersCopy(new_users);
    if (UNLIKELY(new_baseline == NULL))
    {
        usersDestroy(new_users);
        memoryFree(new_users);
        return false;
    }

    users_t *old_baseline = NULL;
    rwlockWriteLock(&ts->users_lock);
    users_t *old_users = ts->users;
    if (UNLIKELY(! authenticationclientApplyLocalTrafficDelta(new_users, old_users, ts->sync_baseline_users)))
    {
        rwlockWriteUnlock(&ts->users_lock);
        authenticationclientDestroyUsers(new_baseline);
        usersDestroy(new_users);
        memoryFree(new_users);
        LOGW("AuthenticationClient: failed to preserve local traffic deltas during GetAllUsers replacement");
        return false;
    }

    ts->users               = new_users;
    old_baseline            = ts->sync_baseline_users;
    ts->sync_baseline_users = new_baseline;
    ts->users_generation += 1U;
    ts->local_config_revision     = config_revision;
    ts->local_stats_revision      = stats_revision;
    ts->local_revision_generation = revision_generation;
    rwlockWriteUnlock(&ts->users_lock);

    if (LIKELY(old_users != NULL))
    {
        usersDestroy(old_users);
        memoryFree(old_users);
    }
    authenticationclientDestroyUsers(old_baseline);

    LOGI("AuthenticationClient: pulled %zu users from server", usersCount(new_users));
    return true;
}

static bool authenticationclientJsonBool(const uint8_t *data, uint32_t data_len, const char *name, bool def)
{
    cJSON *json = cJSON_ParseWithLength((const char *) data, data_len);
    if (UNLIKELY(json == NULL))
    {
        return def;
    }

    const cJSON *item   = cJSON_GetObjectItemCaseSensitive(json, name);
    bool         result = cJSON_IsBool(item) ? cJSON_IsTrue(item) : def;
    cJSON_Delete(json);
    return result;
}

static bool authenticationclientApplyLocalTrafficDelta(users_t *dest, users_t *old_users, users_t *baseline_users)
{
    if (UNLIKELY(dest == NULL || old_users == NULL))
    {
        return true;
    }

    const size_t users_count = usersCount(old_users);
    for (size_t i = 0; i < users_count; ++i)
    {
        user_t *old_user = usersGetAt(old_users, i);
        if (UNLIKELY(old_user == NULL || ! old_user->sha256_pass_valid))
        {
            continue;
        }

        user_stat_t old_stats = {0};
        userGetStats(old_user, &old_stats);

        user_stat_t baseline_stats = {0};
        if (baseline_users != NULL)
        {
            user_t *baseline_user = usersLookupBySHA256(baseline_users, old_user->sha256_pass.bytes);
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
            usersAddTrafficBySHA256(dest, old_user->sha256_pass.bytes, upload_delta, download_delta);
        if (UNLIKELY(result != kUsersUpdateResultOk && result != kUsersUpdateResultUserNotFound))
        {
            return false;
        }
    }

    return true;
}

static void authenticationclientHandleError(tunnel_t *t, uint8_t request_type, const uint8_t *data, uint32_t data_len)
{
    authenticationclient_tstate_t *ts        = tunnelGetState(t);
    const char                    *error     = (const char *) data;
    uint32_t                       error_len = data_len;

    if (UNLIKELY(error_len > 128U))
    {
        error_len = 128U;
    }

    LOGW("AuthenticationClient: request type %u failed: %.*s",
         (unsigned int) request_type,
         (int) error_len,
         error != NULL ? error : "");

    if (request_type == kAuthenticationClientRequestTypeAuthenticate)
    {
        mutexLock(&ts->control_mutex);
        authenticationclientClearSessionLocked(ts);
        mutexUnlock(&ts->control_mutex);
        return;
    }
    if (request_type == kAuthenticationClientRequestTypePushUserStats)
    {
        authenticationclientClearPendingPushUsers(t);
    }

    if (data_len == sizeof("authentication-required") - 1U &&
        memoryCompare(data, "authentication-required", data_len) == 0)
    {
        mutexLock(&ts->control_mutex);
        authenticationclientClearSessionLocked(ts);
        mutexUnlock(&ts->control_mutex);
        discard authenticationclientSendAuthenticate(t);
    }
}

static void authenticationclientHandleResponseFrame(tunnel_t *t, line_t *l, uint8_t response_type,
                                                    uint32_t correlation_id, const uint8_t *data, uint32_t data_len,
                                                    uint64_t config_revision, uint64_t stats_revision)
{
    discard l;

    authenticationclient_tstate_t *ts                  = tunnelGetState(t);
    uint8_t                        request_type        = 0;
    uint64_t                       revision_generation = 0;
    bool                           found               = false;

    mutexLock(&ts->control_mutex);
    found = authenticationclientPendingRemove(ts, correlation_id, &request_type);
    if (found)
    {
        authenticationclientMarkRequestInFlightLocked(ts, request_type, false);
    }
    ts->remote_config_revision = config_revision;
    ts->remote_stats_revision  = stats_revision;
    ts->remote_revision_generation += 1U;
    if (ts->remote_revision_generation == 0)
    {
        ts->remote_revision_generation = 1U;
    }
    revision_generation = ts->remote_revision_generation;
    mutexUnlock(&ts->control_mutex);

    if (UNLIKELY(! found))
    {
        LOGW("AuthenticationClient: received response for unknown correlation id %u", (unsigned int) correlation_id);
        return;
    }

    if (UNLIKELY(response_type == kAuthenticationClientResponseTypeError))
    {
        authenticationclientHandleError(t, request_type, data, data_len);
        return;
    }

    switch (request_type)
    {
    case kAuthenticationClientRequestTypeAuthenticate:
        if (UNLIKELY(response_type != kAuthenticationClientResponseTypeSession ||
                     data_len != kAuthenticationClientSessionTokenSize))
        {
            LOGW("AuthenticationClient: Authenticate returned an invalid session response");
            return;
        }

        mutexLock(&ts->control_mutex);
        memoryCopy(ts->token, data, kAuthenticationClientSessionTokenSize);
        ts->authenticated = true;
        mutexUnlock(&ts->control_mutex);

        LOGI("AuthenticationClient: authenticated as \"%s\"", ts->name);
        discard authenticationclientSendGetAllUsers(t);
        break;

    case kAuthenticationClientRequestTypeGetAllUsers:
        if (UNLIKELY(response_type != kAuthenticationClientResponseTypeUsers))
        {
            LOGW("AuthenticationClient: GetAllUsers returned unexpected response type %u",
                 (unsigned int) response_type);
            return;
        }
        discard authenticationclientReplaceUsersFromJson(
            t, data, data_len, config_revision, stats_revision, revision_generation);
        break;

    case kAuthenticationClientRequestTypePushUserStats: {
        if (UNLIKELY(response_type != kAuthenticationClientResponseTypeOk))
        {
            LOGW("AuthenticationClient: PushUserStats returned unexpected response type %u",
                 (unsigned int) response_type);
            authenticationclientClearPendingPushUsers(t);
            return;
        }
        const bool needs_pull = authenticationclientJsonBool(data, data_len, "needs-pull", false);
        authenticationclientAcknowledgePendingPushUsers(
            t, ! needs_pull, config_revision, stats_revision, revision_generation);
        if (needs_pull)
        {
            discard authenticationclientSendGetAllUsers(t);
        }
        break;
    }

    case kAuthenticationClientRequestTypePing:
        if (response_type != kAuthenticationClientResponseTypePong)
        {
            LOGW("AuthenticationClient: Ping returned unexpected response type %u", (unsigned int) response_type);
        }
        break;

    default:
        break;
    }
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
    while (true)
    {
        uint32_t message_body_len = 0;
        if (! authenticationclientReadMessageHeader(ls, &message_body_len))
        {
            return true;
        }

        if (UNLIKELY(message_body_len < kAuthenticationClientRevisionHeaderSize))
        {
            authenticationclientCloseControlLine(t, l, true);
            return false;
        }
        if (UNLIKELY(message_body_len >
                     kAuthenticationClientMaxResponsePayload + kAuthenticationClientRevisionHeaderSize))
        {
            authenticationclientCloseControlLine(t, l, true);
            return false;
        }

        const size_t message_len = (size_t) kAuthenticationClientMessageHeaderSize + (size_t) message_body_len;
        if (bufferstreamGetBufLen(&ls->read_stream) < message_len)
        {
            return true;
        }

        sbuf_t *payload = bufferstreamReadExact(&ls->read_stream, message_len);
        sbufShiftRight(payload, kAuthenticationClientMessageHeaderSize);

        const uint8_t *revision_ptr    = sbufGetRawPtr(payload);
        const uint64_t config_revision = authenticationclientReadNetworkUI64(revision_ptr);
        const uint64_t stats_revision  = authenticationclientReadNetworkUI64(revision_ptr + sizeof(uint64_t));
        sbufShiftRight(payload, kAuthenticationClientRevisionHeaderSize);

        if (UNLIKELY(! authenticationclientValidateResponsePayload(payload)))
        {
            lineReuseBuffer(l, payload);
            authenticationclientCloseControlLine(t, l, true);
            return false;
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

            authenticationclientHandleResponseFrame(
                t, l, response_type, correlation_id, response_data, response_data_len, config_revision, stats_revision);

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

    if (UNLIKELY(getWID() != 0))
    {
        LOGF("AuthenticationClient: control line must be opened on worker 0");
        terminateProgram(1);
        return;
    }

    mutexLock(&ts->control_mutex);
    if (UNLIKELY(ts->stopping || ts->control_line != NULL))
    {
        mutexUnlock(&ts->control_mutex);
        return;
    }
    authenticationclientClearSessionLocked(ts);
    ts->connected     = false;
    ts->write_paused  = false;
    ts->pending_count = 0;
    mutexUnlock(&ts->control_mutex);

    line_t                        *line = lineCreate(tunnelchainGetLinePools(tunnelGetChain(t)), 0);
    authenticationclient_lstate_t *ls   = lineGetState(line, t);
    authenticationclientLinestateInitialize(ls, lineGetBufferPool(line));

    mutexLock(&ts->control_mutex);
    ts->control_line = line;
    mutexUnlock(&ts->control_mutex);

    if (UNLIKELY(! withLineLocked(line, tunnelNextUpStreamInit, t)))
    {
        return;
    }
}

static void authenticationclientOpenControlLineOnWorker0(void *worker_ptr, void *arg1, void *arg2, void *arg3)
{
    discard worker_ptr;
    discard arg2;
    discard arg3;

    authenticationclientOpenControlLine(arg1);
}

void authenticationclientCloseControlLine(tunnel_t *t, line_t *l, bool propagate_finish)
{
    authenticationclient_tstate_t *ts = tunnelGetState(t);

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

    authenticationclient_lstate_t *ls = lineGetState(l, t);
    authenticationclientLinestateDestroy(ls);

    if (propagate_finish && LIKELY(lineIsAlive(l)))
    {
        tunnelNextUpStreamFinish(t, l);
    }

    if (LIKELY(lineIsAlive(l)))
    {
        lineDestroy(l);
    }
}

void authenticationclientScheduleReconnect(tunnel_t *t)
{
    authenticationclient_tstate_t *ts              = tunnelGetState(t);
    bool                           should_schedule = false;

    if (getWID() != 0)
    {
        sendWorkerMessageForceQueue(0, authenticationclientOpenControlLineOnWorker0, t, NULL, NULL);
        return;
    }

    mutexLock(&ts->control_mutex);
    should_schedule = ts->started && ! ts->stopping && ts->control_line == NULL;
    mutexUnlock(&ts->control_mutex);
    if (UNLIKELY(! should_schedule))
    {
        return;
    }

    if (ts->reconnect_interval_ms == 0)
    {
        authenticationclientOpenControlLine(t);
        return;
    }

    if (UNLIKELY(ts->reconnect_timer != NULL))
    {
        wtimerReset(ts->reconnect_timer, ts->reconnect_interval_ms);
        return;
    }

    ts->reconnect_timer =
        wtimerAdd(getWorkerLoop(0), authenticationclientReconnectTimerCallback, ts->reconnect_interval_ms, 1);
    if (UNLIKELY(ts->reconnect_timer == NULL))
    {
        LOGF("AuthenticationClient: failed to create reconnect timer");
        terminateProgram(1);
        return;
    }
    weventSetUserData(ts->reconnect_timer, t);
}

void authenticationclientReconnectTimerCallback(wtimer_t *timer)
{
    tunnel_t *t = weventGetUserdata(timer);
    if (UNLIKELY(t == NULL))
    {
        return;
    }

    authenticationclient_tstate_t *ts = tunnelGetState(t);
    if (LIKELY(ts->reconnect_timer == timer))
    {
        ts->reconnect_timer = NULL;
    }

    authenticationclientOpenControlLine(t);
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

void authenticationclientStartSyncTimer(tunnel_t *t)
{
    authenticationclient_tstate_t *ts               = tunnelGetState(t);
    const uint32_t                 sync_interval_ms = authenticationclientSyncInterval(ts);

    if (sync_interval_ms == 0 || ts->sync_timer != NULL)
    {
        return;
    }

    const uint32_t now_ms = getTickMS();
    ts->last_pull_sync_ms = now_ms;
    ts->last_push_sync_ms = now_ms;

    ts->sync_timer = wtimerAdd(getWorkerLoop(0), authenticationclientSyncTimerCallback, sync_interval_ms, INFINITE);
    if (UNLIKELY(ts->sync_timer == NULL))
    {
        LOGF("AuthenticationClient: failed to create sync timer");
        terminateProgram(1);
        return;
    }
    weventSetUserData(ts->sync_timer, t);
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

    if (push_due)
    {
        discard authenticationclientSendPushUserStats(t);
    }

    if (ts->pull_interval_ms == 0)
    {
        return;
    }

    if (! authenticationclientShouldSendGetAllUsers(t, pull_due))
    {
        return;
    }

    ts->last_pull_sync_ms = now_ms;
    discard authenticationclientSendGetAllUsers(t);
}
