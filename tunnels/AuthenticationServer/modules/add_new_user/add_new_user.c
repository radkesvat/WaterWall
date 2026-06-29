#include "modules/add_new_user/add_new_user.h"

#include "loggers/network_logger.h"

static const char *authenticationserverUsersAddResultError(users_add_result_t result)
{
    switch (result)
    {
    case kUsersAddResultOk:
        return "ok";
    case kUsersAddResultInvalidArgument:
        return "invalid-add-user-request";
    case kUsersAddResultInvalidJson:
        return "invalid-user-json";
    case kUsersAddResultInvalidUser:
        return "invalid-user";
    case kUsersAddResultDuplicateName:
        return "user-name-exists";
    case kUsersAddResultDuplicateId:
        return "user-id-exists";
    case kUsersAddResultDuplicateSHA224:
        return "user-sha224-exists";
    case kUsersAddResultDuplicateSHA256:
        return "user-sha256-exists";
    case kUsersAddResultDuplicateUUID:
        return "user-uuid-exists";
    case kUsersAddResultDuplicateWireGuardPublicKey:
        return "user-wireguard-publickey-exists";
    case kUsersAddResultAllocationFailed:
        return "allocation-failed";
    case kUsersAddResultCommitFailed:
        return "user-add-failed";
    }

    return "user-add-failed";
}

sbuf_t *authenticationserverAddNewUserHandle(const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                             tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                             const uint8_t *request_data, uint32_t request_data_len)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    uint8_t                        added_sha256[SHA256_DIGEST_SIZE];
    user_t                         user;
    discard                        session;

    if (UNLIKELY(request_data_len == 0))
    {
        LOGW("AuthenticationServer: AddNewUser received an empty JSON payload");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-user-json");
    }

    cJSON *user_json = cJSON_ParseWithLength((const char *) request_data, request_data_len);
    if (UNLIKELY(user_json == NULL))
    {
        LOGW("AuthenticationServer: AddNewUser received malformed JSON");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-user-json");
    }
    if (UNLIKELY(! cJSON_IsObject(user_json)))
    {
        LOGW("AuthenticationServer: AddNewUser JSON payload is not a user object");
        cJSON_Delete(user_json);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-user-json");
    }

    memoryZero(&user, sizeof(user));
    if (UNLIKELY(! userCreateFromJson(&user, user_json)))
    {
        LOGW("AuthenticationServer: AddNewUser JSON payload is not a valid user");
        cJSON_Delete(user_json);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-user");
    }
    cJSON_Delete(user_json);

    if (UNLIKELY(! authenticationserverUserHasRequiredId(&user)))
    {
        LOGW("AuthenticationServer: AddNewUser rejected user JSON: user-id-required");
        userDestroy(&user);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "user-id-required");
    }

    memoryCopy(added_sha256, user.sha256_pass.bytes, SHA256_DIGEST_SIZE);
    recursivemutexLock(&ts->database_mutex);
    users_add_result_t add_result = usersAddUserChecked(&ts->store.users, &user);
    userDestroy(&user);

    if (UNLIKELY(add_result != kUsersAddResultOk))
    {
        const char *error = authenticationserverUsersAddResultError(add_result);
        LOGW("AuthenticationServer: AddNewUser rejected user JSON: %s", error);
        recursivemutexUnlock(&ts->database_mutex);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, error);
    }

    if (UNLIKELY(! authenticationserverSaveDatabase(ts)))
    {
        LOGW("AuthenticationServer: AddNewUser failed to save database after adding user; rolling back in-memory add");
        if (UNLIKELY(! usersRemoveUserBySHA256(&ts->store.users, added_sha256)))
        {
            LOGW("AuthenticationServer: AddNewUser could not roll back the in-memory user after save failure");
        }
        recursivemutexUnlock(&ts->database_mutex);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "database-save-failed");
    }
    authenticationserverBumpConfigRevision(t);
    recursivemutexUnlock(&ts->database_mutex);

    static const char ok[] = "user-added";
    LOGI("AuthenticationServer: AddNewUser added a new user and saved the database");
    return authenticationserverCreateResponseFrame(
        l, kAuthenticationServerResponseTypeOk, correlation_id, (const uint8_t *) ok, (uint32_t) (sizeof(ok) - 1U));
}
