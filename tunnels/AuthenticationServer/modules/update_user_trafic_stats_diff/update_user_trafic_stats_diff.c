#include "modules/update_user_trafic_stats_diff/update_user_trafic_stats_diff.h"

#include "loggers/network_logger.h"

static const char *authenticationserverTrafficDiffResultError(users_update_result_t result)
{
    switch (result)
    {
    case kUsersUpdateResultOk:
        return "ok";
    case kUsersUpdateResultInvalidArgument:
    case kUsersUpdateResultUnknownFields:
    case kUsersUpdateResultInvalidRecordStatInterval:
        return "invalid-update-user-traffic-stats-diff-request";
    case kUsersUpdateResultAllocationFailed:
        return "allocation-failed";
    case kUsersUpdateResultUserNotFound:
        return "user-not-found";
    case kUsersUpdateResultDuplicateName:
    case kUsersUpdateResultPasswordUpdateFailed:
        return "user-update-failed";
    }

    return "user-update-failed";
}

sbuf_t *authenticationserverUpdateUserTraficStatsDiffHandle(
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize], tunnel_t *t, line_t *l,
    authenticationserver_session_t *session, const uint8_t *request_data, uint32_t request_data_len)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    user_t                         user;
    discard                        session;

    if (request_data_len == 0)
    {
        LOGW("AuthenticationServer: UpdateUserTraficStatsDiff received an empty JSON payload");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-user-json");
    }

    cJSON *user_json = cJSON_ParseWithLength((const char *) request_data, request_data_len);
    if (user_json == NULL)
    {
        LOGW("AuthenticationServer: UpdateUserTraficStatsDiff received malformed JSON");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-user-json");
    }
    if (! cJSON_IsObject(user_json))
    {
        LOGW("AuthenticationServer: UpdateUserTraficStatsDiff JSON payload is not a user object");
        cJSON_Delete(user_json);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-user-json");
    }

    memoryZero(&user, sizeof(user));
    if (! userCreateFromJson(&user, user_json))
    {
        LOGW("AuthenticationServer: UpdateUserTraficStatsDiff JSON payload is not a valid user");
        cJSON_Delete(user_json);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-user");
    }
    cJSON_Delete(user_json);

    users_update_result_t result =
        usersAddTrafficBySHA256(&ts->store.users, user.sha256_pass.bytes, user.stats.traffic.u, user.stats.traffic.d);
    const bool traffic_changed = user.stats.traffic.u > 0 || user.stats.traffic.d > 0;
    userDestroy(&user);

    if (result != kUsersUpdateResultOk)
    {
        const char *error = authenticationserverTrafficDiffResultError(result);
        LOGW("AuthenticationServer: UpdateUserTraficStatsDiff rejected user JSON: %s", error);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, error);
    }

    if (traffic_changed)
    {
        authenticationserverBumpStatsRevision(t);
    }

    static const char ok[] = "user-traffic-stats-updated";
    LOGI("AuthenticationServer: UpdateUserTraficStatsDiff added traffic stats to a user in memory");
    return authenticationserverCreateResponseFrame(
        l, kAuthenticationServerResponseTypeOk, correlation_id, (const uint8_t *) ok, (uint32_t) (sizeof(ok) - 1U));
}
