#include "modules/push_user_stats/push_user_stats.h"

#include "loggers/network_logger.h"
#include "utils/json_helpers.h"

typedef struct authenticationserver_stats_hint_s
{
    uint8_t  sha256[SHA256_DIGEST_SIZE];
    uint64_t upload;
    uint64_t download;
    bool     upload_present;
    bool     download_present;
} authenticationserver_stats_hint_t;

typedef struct authenticationserver_stats_hint_list_s
{
    authenticationserver_stats_hint_t *items;
    size_t                             count;
    size_t                             capacity;
} authenticationserver_stats_hint_list_t;

typedef struct authenticationserver_stats_delta_s
{
    uint8_t  sha256[SHA256_DIGEST_SIZE];
    uint64_t upload;
    uint64_t download;
    uint64_t first_usage_at_ms;
    bool     first_usage_present;
} authenticationserver_stats_delta_t;

static bool authenticationserverPushStatsStringIsEmpty(const char *value)
{
    return value == NULL || value[0] == '\0';
}

static const cJSON *authenticationserverPushStatsJsonGetItem(const cJSON *json_obj, const char *key)
{
    if (UNLIKELY(! cJSON_IsObject(json_obj)))
    {
        return NULL;
    }
    return cJSON_GetObjectItemCaseSensitive(json_obj, key);
}

static const cJSON *authenticationserverPushStatsJsonGetItem2(const cJSON *json_obj, const char *primary,
                                                              const char *fallback)
{
    const cJSON *item = authenticationserverPushStatsJsonGetItem(json_obj, primary);
    if (LIKELY(item != NULL))
    {
        return item;
    }
    return authenticationserverPushStatsJsonGetItem(json_obj, fallback);
}

static bool authenticationserverPushStatsReadOptionalCounter(const cJSON *json_obj, const char *primary,
                                                             const char *fallback, uint64_t *value, bool *present)
{
    const cJSON *item = authenticationserverPushStatsJsonGetItem2(json_obj, primary, fallback);
    *present          = false;

    if (item == NULL || cJSON_IsNull(item))
    {
        return true;
    }

    *present = true;
    return getUint64FromJson(value, item);
}

static bool authenticationserverPushStatsReadHintTraffic(const cJSON                       *hint_json,
                                                         authenticationserver_stats_hint_t *hint)
{
    const cJSON *stats = authenticationserverPushStatsJsonGetItem(hint_json, "stats");
    if (stats == NULL || cJSON_IsNull(stats))
    {
        return true;
    }
    if (UNLIKELY(! cJSON_IsObject(stats)))
    {
        return false;
    }

    const cJSON *traffic = authenticationserverPushStatsJsonGetItem(stats, "traffic");
    if (traffic == NULL || cJSON_IsNull(traffic))
    {
        return true;
    }
    if (UNLIKELY(! cJSON_IsObject(traffic)))
    {
        return false;
    }

    if (UNLIKELY(! authenticationserverPushStatsReadOptionalCounter(
                     traffic, "up", "u", &hint->upload, &hint->upload_present) ||
                 ! authenticationserverPushStatsReadOptionalCounter(
                     traffic, "down", "d", &hint->download, &hint->download_present)))
    {
        return false;
    }

    return true;
}

static bool authenticationserverPushStatsHintListReserve(authenticationserver_stats_hint_list_t *hints, size_t count)
{
    if (LIKELY(count <= hints->capacity))
    {
        return true;
    }

    size_t new_capacity = hints->capacity == 0 ? 8U : hints->capacity;
    while (new_capacity < count)
    {
        if (UNLIKELY(new_capacity > SIZE_MAX / 2U))
        {
            return false;
        }
        new_capacity *= 2U;
    }
    if (UNLIKELY(new_capacity > SIZE_MAX / sizeof(*hints->items)))
    {
        return false;
    }

    authenticationserver_stats_hint_t *new_items = memoryReAllocate(hints->items, sizeof(*new_items) * new_capacity);
    if (UNLIKELY(new_items == NULL))
    {
        return false;
    }

    hints->items    = new_items;
    hints->capacity = new_capacity;
    return true;
}

static bool authenticationserverPushStatsHintListContains(const authenticationserver_stats_hint_list_t *hints,
                                                          const uint8_t sha256[SHA256_DIGEST_SIZE])
{
    for (size_t i = 0; i < hints->count; ++i)
    {
        if (UNLIKELY(memoryEqual(hints->items[i].sha256, sha256, SHA256_DIGEST_SIZE)))
        {
            return true;
        }
    }

    return false;
}

static bool authenticationserverPushStatsHintListAppend(authenticationserver_stats_hint_list_t  *hints,
                                                        const authenticationserver_stats_hint_t *hint)
{
    if (UNLIKELY(authenticationserverPushStatsHintListContains(hints, hint->sha256)))
    {
        LOGW("AuthenticationServer: PushUserStats rejected duplicate user stats hint");
        return false;
    }

    if (UNLIKELY(! authenticationserverPushStatsHintListReserve(hints, hints->count + 1U)))
    {
        return false;
    }

    hints->items[hints->count] = *hint;
    hints->count += 1U;
    return true;
}

static void authenticationserverPushStatsHintListDestroy(authenticationserver_stats_hint_list_t *hints)
{
    if (UNLIKELY(hints == NULL))
    {
        return;
    }

    memoryFree(hints->items);
    memoryZero(hints, sizeof(*hints));
}

static bool authenticationserverPushStatsJsonLooksLikeHint(const cJSON *json)
{
    return authenticationserverPushStatsJsonGetItem(json, "password") != NULL ||
           authenticationserverPushStatsJsonGetItem(json, "pass") != NULL;
}

static bool authenticationserverPushStatsAddHintFromJson(authenticationserver_stats_hint_list_t *hints,
                                                         const cJSON                            *hint_json)
{
    if (UNLIKELY(! cJSON_IsObject(hint_json)))
    {
        return false;
    }

    const cJSON *password_json = authenticationserverPushStatsJsonGetItem2(hint_json, "password", "pass");
    if (UNLIKELY(! cJSON_IsString(password_json) ||
                 authenticationserverPushStatsStringIsEmpty(password_json->valuestring)))
    {
        return false;
    }

    const size_t password_len = stringLength(password_json->valuestring);
    if (UNLIKELY(password_len > kAuthenticationServerMaxPasswordLength))
    {
        return false;
    }

    authenticationserver_stats_hint_t hint   = {0};
    sha256_hash_t                     sha256 = {0};
    if (UNLIKELY(wCryptoSHA256(&sha256, (const unsigned char *) password_json->valuestring, password_len) !=
                 kWCryptoOk))
    {
        memoryZero(&sha256, sizeof(sha256));
        return false;
    }
    memoryCopy(hint.sha256, sha256.bytes, SHA256_DIGEST_SIZE);
    memoryZero(&sha256, sizeof(sha256));

    if (UNLIKELY(! authenticationserverPushStatsReadHintTraffic(hint_json, &hint)))
    {
        return false;
    }

    if (UNLIKELY(! hint.upload_present && ! hint.download_present))
    {
        return false;
    }

    return authenticationserverPushStatsHintListAppend(hints, &hint);
}

static bool authenticationserverPushStatsFeedJsonHints(authenticationserver_stats_hint_list_t *hints,
                                                       const cJSON                            *json);

static bool authenticationserverPushStatsFeedArrayHints(authenticationserver_stats_hint_list_t *hints,
                                                        const cJSON                            *array)
{
    const cJSON *entry = NULL;

    cJSON_ArrayForEach(entry, array)
    {
        if (UNLIKELY(! authenticationserverPushStatsAddHintFromJson(hints, entry)))
        {
            return false;
        }
    }

    return true;
}

static bool authenticationserverPushStatsFeedObjectMapHints(authenticationserver_stats_hint_list_t *hints,
                                                            const cJSON                            *object)
{
    const cJSON *entry = NULL;

    cJSON_ArrayForEach(entry, object)
    {
        if (UNLIKELY(! authenticationserverPushStatsAddHintFromJson(hints, entry)))
        {
            return false;
        }
    }

    return true;
}

static bool authenticationserverPushStatsFeedJsonHints(authenticationserver_stats_hint_list_t *hints, const cJSON *json)
{
    if (json == NULL || cJSON_IsNull(json))
    {
        return true;
    }
    if (cJSON_IsArray(json))
    {
        return authenticationserverPushStatsFeedArrayHints(hints, json);
    }
    if (UNLIKELY(! cJSON_IsObject(json)))
    {
        return false;
    }
    if (json->child == NULL)
    {
        return true;
    }

    const cJSON *users_array = cJSON_GetObjectItemCaseSensitive(json, "users");
    if (users_array != NULL)
    {
        if (cJSON_IsNull(users_array))
        {
            return true;
        }
        if (UNLIKELY(! cJSON_IsArray(users_array)))
        {
            return false;
        }
        return authenticationserverPushStatsFeedArrayHints(hints, users_array);
    }
    if (authenticationserverPushStatsJsonLooksLikeHint(json))
    {
        return authenticationserverPushStatsAddHintFromJson(hints, json);
    }

    return authenticationserverPushStatsFeedObjectMapHints(hints, json);
}

static bool authenticationserverPushStatsLoadHints(const uint8_t *request_data, uint32_t request_data_len,
                                                   authenticationserver_stats_hint_list_t *hints)
{
    if (UNLIKELY(request_data_len == 0))
    {
        return false;
    }

    cJSON *json = cJSON_ParseWithLength((const char *) request_data, request_data_len);
    if (UNLIKELY(json == NULL))
    {
        return false;
    }

    bool ok = authenticationserverPushStatsFeedJsonHints(hints, json);
    cJSON_Delete(json);
    return ok;
}

static bool authenticationserverPushStatsBuildDeltas(tunnel_t *t, authenticationserver_session_t *session,
                                                     const authenticationserver_stats_hint_list_t *hints,
                                                     uint64_t                                      server_now_ms,
                                                     authenticationserver_stats_delta_t          **deltas_out,
                                                     size_t                                       *delta_count_out)
{
    authenticationserver_tstate_t      *ts          = tunnelGetState(t);
    authenticationserver_stats_delta_t *deltas      = NULL;
    size_t                              delta_count = 0;

    if (hints->count > 0)
    {
        deltas = memoryAllocateZero(sizeof(*deltas) * hints->count);
        if (UNLIKELY(deltas == NULL))
        {
            return false;
        }
    }

    for (size_t i = 0; i < hints->count; ++i)
    {
        const authenticationserver_stats_hint_t *hint = &hints->items[i];
        user_t *baseline_user                         = usersLookupBySHA256(&session->baseline_users, hint->sha256);
        user_t *store_user                            = usersLookupBySHA256(&ts->store.users, hint->sha256);
        if (UNLIKELY(baseline_user == NULL || store_user == NULL))
        {
            LOGW("AuthenticationServer: PushUserStats received a user that is not present in the session baseline or "
                 "authoritative store");
            memoryFree(deltas);
            return false;
        }

        user_stat_t baseline_stats = {0};
        userGetStats(baseline_user, &baseline_stats);

        uint64_t upload_delta = 0;
        if (hint->upload_present)
        {
            if (UNLIKELY(hint->upload < baseline_stats.traffic.u))
            {
                LOGW("AuthenticationServer: PushUserStats rejected backwards upload traffic counter");
                memoryFree(deltas);
                return false;
            }
            upload_delta = hint->upload - baseline_stats.traffic.u;
        }

        uint64_t download_delta = 0;
        if (hint->download_present)
        {
            if (UNLIKELY(hint->download < baseline_stats.traffic.d))
            {
                LOGW("AuthenticationServer: PushUserStats rejected backwards download traffic counter");
                memoryFree(deltas);
                return false;
            }
            download_delta = hint->download - baseline_stats.traffic.d;
        }

        user_time_info_t store_timeinfo = {0};
        userGetTimeInfo(store_user, &store_timeinfo);

        uint64_t first_usage_at_ms = 0;
        if ((upload_delta != 0 || download_delta != 0) && store_timeinfo.first_usage_at_ms == 0)
        {
            first_usage_at_ms = server_now_ms;
        }

        if (UNLIKELY(upload_delta == 0 && download_delta == 0 && first_usage_at_ms == 0))
        {
            continue;
        }

        memoryCopy(deltas[delta_count].sha256, hint->sha256, SHA256_DIGEST_SIZE);
        deltas[delta_count].upload              = upload_delta;
        deltas[delta_count].download            = download_delta;
        deltas[delta_count].first_usage_at_ms   = first_usage_at_ms;
        deltas[delta_count].first_usage_present = first_usage_at_ms != 0;
        ++delta_count;
    }

    *deltas_out      = deltas;
    *delta_count_out = delta_count;
    return true;
}

static bool authenticationserverPushStatsApplyDeltas(tunnel_t *t, authenticationserver_session_t *session,
                                                     const authenticationserver_stats_delta_t *deltas,
                                                     size_t                                    delta_count)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    for (size_t i = 0; i < delta_count; ++i)
    {
        if (deltas[i].upload != 0 || deltas[i].download != 0)
        {
            users_update_result_t result =
                usersAddTrafficBySHA256(&ts->store.users, deltas[i].sha256, deltas[i].upload, deltas[i].download);
            if (UNLIKELY(result != kUsersUpdateResultOk))
            {
                return false;
            }

            result = usersAddTrafficBySHA256(
                &session->baseline_users, deltas[i].sha256, deltas[i].upload, deltas[i].download);
            if (UNLIKELY(result != kUsersUpdateResultOk))
            {
                return false;
            }
        }

        if (deltas[i].first_usage_present)
        {
            users_update_result_t result = usersSetFirstUsageIfMissingBySHA256(
                &ts->store.users, deltas[i].sha256, deltas[i].first_usage_at_ms, NULL);
            if (UNLIKELY(result != kUsersUpdateResultOk))
            {
                return false;
            }

            result = usersSetFirstUsageIfMissingBySHA256(
                &session->baseline_users, deltas[i].sha256, deltas[i].first_usage_at_ms, NULL);
            if (UNLIKELY(result != kUsersUpdateResultOk))
            {
                return false;
            }
        }
    }

    return true;
}

static bool authenticationserverPushStatsDeltasRequirePull(const authenticationserver_stats_delta_t *deltas,
                                                           size_t                                    delta_count)
{
    for (size_t i = 0; i < delta_count; ++i)
    {
        if (deltas[i].first_usage_present)
        {
            return true;
        }
    }

    return false;
}

static sbuf_t *authenticationserverPushStatsStatusResponse(
    tunnel_t *t, line_t *l, const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
    authenticationserver_session_t *session, size_t delta_count, bool force_needs_pull)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    const bool needs_pull = force_needs_pull || session->baseline_config_revision != ts->store.config_revision ||
                            session->baseline_stats_revision != ts->store.stats_revision;

    cJSON *json = cJSON_CreateObject();
    if (UNLIKELY(json == NULL))
    {
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "stats-push-response-failed");
    }

    if (UNLIKELY(! cJSON_AddStringToObject(json, "status", "stats-updated") ||
                 ! jsonAddUint64ToObject(json, "applied-deltas", (uint64_t) delta_count) ||
                 (needs_pull ? cJSON_AddTrueToObject(json, "needs-pull") == NULL
                             : cJSON_AddFalseToObject(json, "needs-pull") == NULL) ||
                 ! jsonAddUint64ToObject(json, "config-revision", ts->store.config_revision) ||
                 ! jsonAddUint64ToObject(json, "stats-revision", ts->store.stats_revision)))
    {
        cJSON_Delete(json);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "stats-push-response-failed");
    }

    char *text = cJSON_PrintUnformatted(json);
    cJSON_Delete(json);
    if (UNLIKELY(text == NULL))
    {
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "stats-push-response-failed");
    }

    sbuf_t *response = authenticationserverCreateResponseFrame(
        l, kAuthenticationServerResponseTypeOk, correlation_id, (const uint8_t *) text, (uint32_t) stringLength(text));
    cJSON_free(text);
    return response;
}

sbuf_t *authenticationserverPushUserStatsHandle(const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                                tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                                const uint8_t *request_data, uint32_t request_data_len)
{
    authenticationserver_tstate_t         *ts          = tunnelGetState(t);
    authenticationserver_stats_hint_list_t hints       = {0};
    authenticationserver_stats_delta_t    *deltas      = NULL;
    size_t                                 delta_count = 0;
    bool                                   force_pull  = false;

    if (UNLIKELY(session == NULL))
    {
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "authentication-required");
    }

    if (UNLIKELY(! authenticationserverPushStatsLoadHints(request_data, request_data_len, &hints)))
    {
        authenticationserverPushStatsHintListDestroy(&hints);
        LOGW("AuthenticationServer: PushUserStats received invalid users stats hint JSON");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-users-json");
    }

    const uint64_t old_config_revision = session->baseline_config_revision;
    const uint64_t old_stats_revision  = session->baseline_stats_revision;
    const bool     config_was_current  = old_config_revision == ts->store.config_revision;
    const bool     stats_was_current   = old_stats_revision == ts->store.stats_revision;

    if (UNLIKELY(
            ! authenticationserverPushStatsBuildDeltas(t, session, &hints, getTimeOfDayMS(), &deltas, &delta_count)))
    {
        authenticationserverPushStatsHintListDestroy(&hints);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-stats-baseline");
    }

    if (UNLIKELY(! authenticationserverPushStatsApplyDeltas(t, session, deltas, delta_count)))
    {
        memoryFree(deltas);
        authenticationserverPushStatsHintListDestroy(&hints);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "stats-merge-failed");
    }

    if (delta_count > 0)
    {
        authenticationserverBumpStatsRevision(t);
    }
    force_pull = authenticationserverPushStatsDeltasRequirePull(deltas, delta_count);

    if (LIKELY(config_was_current))
    {
        session->baseline_config_revision = ts->store.config_revision;
    }
    if (LIKELY(stats_was_current))
    {
        session->baseline_stats_revision = ts->store.stats_revision;
    }

    sbuf_t *response =
        authenticationserverPushStatsStatusResponse(t, l, correlation_id, session, delta_count, force_pull);

    memoryFree(deltas);
    authenticationserverPushStatsHintListDestroy(&hints);
    return response;
}
