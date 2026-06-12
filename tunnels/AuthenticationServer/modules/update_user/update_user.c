#include "modules/update_user/update_user.h"

#include "loggers/network_logger.h"

static const char *authenticationserverUsersUpdateResultError(users_update_result_t result)
{
    switch (result)
    {
    case kUsersUpdateResultOk:
        return "ok";
    case kUsersUpdateResultInvalidArgument:
    case kUsersUpdateResultUnknownFields:
    case kUsersUpdateResultInvalidRecordStatInterval:
        return "invalid-update-user-request";
    case kUsersUpdateResultAllocationFailed:
        return "allocation-failed";
    case kUsersUpdateResultUserNotFound:
        return "user-not-found";
    case kUsersUpdateResultDuplicateName:
        return "user-name-exists";
    case kUsersUpdateResultPasswordUpdateFailed:
        return "password-update-disabled";
    }

    return "user-update-failed";
}

static user_update_t authenticationserverUpdateFromUser(const user_t *user)
{
    user_update_t update = {
        .mask = kUserUpdateName | kUserUpdateEmail | kUserUpdateNotes | kUserUpdateGid | kUserUpdateEnabled |
                kUserUpdateLimit | kUserUpdateTimeInfo | kUserUpdateStats | kUserUpdateRecordStatInterval,
        .name                    = user->name,
        .email                   = user->email,
        .notes                   = user->notes,
        .gid                     = user->gid,
        .enabled                 = user->enabled,
        .limit                   = user->limit,
        .timeinfo                = user->timeinfo,
        .stats                   = user->stats,
        .record_stat_interval_ms = user->record_stat_interval_ms,
    };

    return update;
}

sbuf_t *authenticationserverUpdateUserHandle(const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                             tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                             const uint8_t *request_data, uint32_t request_data_len)
{
    user_t  user;
    discard session;

    if (request_data_len == 0)
    {
        LOGW("AuthenticationServer: UpdateUser received an empty JSON payload");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-user-json");
    }

    cJSON *user_json = cJSON_ParseWithLength((const char *) request_data, request_data_len);
    if (user_json == NULL)
    {
        LOGW("AuthenticationServer: UpdateUser received malformed JSON");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-user-json");
    }
    if (! cJSON_IsObject(user_json))
    {
        LOGW("AuthenticationServer: UpdateUser JSON payload is not a user object");
        cJSON_Delete(user_json);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-user-json");
    }

    memoryZero(&user, sizeof(user));
    if (! userCreateFromJson(&user, user_json))
    {
        LOGW("AuthenticationServer: UpdateUser JSON payload is not a valid user");
        cJSON_Delete(user_json);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-user");
    }
    cJSON_Delete(user_json);

    user_update_t         update = authenticationserverUpdateFromUser(&user);
    users_update_result_t result =
        authenticationserverUpdateUserBySHA256AndBumpConfigRevision(t, user.sha256_pass.bytes, &update);
    userDestroy(&user);

    if (result != kUsersUpdateResultOk)
    {
        const char *error = authenticationserverUsersUpdateResultError(result);
        LOGW("AuthenticationServer: UpdateUser rejected user JSON: %s", error);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, error);
    }
    static const char ok[] = "user-updated";
    LOGI("AuthenticationServer: UpdateUser updated a user in memory");
    return authenticationserverCreateResponseFrame(
        l, kAuthenticationServerResponseTypeOk, correlation_id, (const uint8_t *) ok, (uint32_t) (sizeof(ok) - 1U));
}
