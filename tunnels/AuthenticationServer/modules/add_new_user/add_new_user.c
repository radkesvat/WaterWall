#include "modules/add_new_user/add_new_user.h"
#include "AuthenticationServer/api.h"
#include "AuthenticationServer/audit.h"

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
    case kUsersAddResultInvalidWireGuardAllowedIps:
        return "invalid-wireguard-allowed-ips";
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
    case kUsersAddResultDuplicateWireGuardAllowedIps:
        return "user-wireguard-allowed-ips-overlap";
    case kUsersAddResultStorageUnavailable:
        return "storage-unavailable";
    case kUsersAddResultTooLarge:
        return "user-too-large";
    /* Bounded API-only refusals are unreachable through this blocking producer
     * path. Keep its existing generic diagnostic if that contract changes. */
    case kUsersAddResultBusy:
    case kUsersAddResultResourceLimit:
    case kUsersAddResultTimeout:
    case kUsersAddResultPrecommitRejected:
    case kUsersAddResultCreationFailed:
        return "user-add-failed";
    }

    return "user-add-failed";
}

static sbuf_t *authenticationserverAddUserRejected(tunnel_t *t, line_t *line, authenticationserver_session_t *session,
                                                   const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                                   uint64_t id, const char *error)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    authenticationserverAuditRecordProducer(
        ts->audit, session != NULL ? session->client_name : NULL, "AddNewUser", id, 0, 0, error);
    return authenticationserverCreateErrorResponseFrame(line, correlation_id, error);
}

sbuf_t *authenticationserverAddNewUserHandle(const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                             tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                             const uint8_t *request_data, uint32_t request_data_len)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    user_t                         user;
    uint64_t                       audit_id = 0;

    if (ts->store.config_revision == UINT64_MAX)
        return authenticationserverAddUserRejected(t, l, session, correlation_id, audit_id, "revision-exhausted");

    if (UNLIKELY(request_data_len == 0))
    {
        if (ts->verbose)
            LOGD("AuthenticationServer: AddNewUser received an empty JSON payload");
        return authenticationserverAddUserRejected(t, l, session, correlation_id, audit_id, "invalid-user-json");
    }

    cJSON *user_json = configLexicalParseBoundedQuietWithCleanup(
        (const char *) request_data, request_data_len, 4, 256, authenticationserverWipeJsonStrings);
    if (UNLIKELY(user_json == NULL))
    {
        if (ts->verbose)
            LOGD("AuthenticationServer: AddNewUser received malformed JSON");
        return authenticationserverAddUserRejected(t, l, session, correlation_id, audit_id, "invalid-user-json");
    }
    if (UNLIKELY(! cJSON_IsObject(user_json)))
    {
        if (ts->verbose)
            LOGD("AuthenticationServer: AddNewUser JSON payload is not a user object");
        authenticationserverWipeJsonStrings(user_json);
        cJSON_Delete(user_json);
        return authenticationserverAddUserRejected(t, l, session, correlation_id, audit_id, "invalid-user-json");
    }
    if (UNLIKELY(! authenticationserverUserJsonWireGuardAllowedIpsValid(user_json)))
    {
        if (ts->verbose)
            LOGD("AuthenticationServer: AddNewUser rejected user JSON: invalid-wireguard-allowed-ips");
        authenticationserverWipeJsonStrings(user_json);
        cJSON_Delete(user_json);
        return authenticationserverAddUserRejected(
            t, l, session, correlation_id, audit_id, "invalid-wireguard-allowed-ips");
    }

    memoryZero(&user, sizeof(user));
    const user_json_result_t create_result = userCreateFromJsonResult(&user, user_json);
    if (UNLIKELY(create_result != kUserJsonOk))
    {
        const bool resource_failure = create_result == kUserJsonResourceFailure;
        if (resource_failure)
            LOGW("AuthenticationServer: AddNewUser could not initialize user resources");
        else if (ts->verbose)
            LOGD("AuthenticationServer: AddNewUser JSON payload is not a valid user");
        authenticationserverWipeJsonStrings(user_json);
        cJSON_Delete(user_json);
        return authenticationserverAddUserRejected(
            t, l, session, correlation_id, audit_id, resource_failure ? "storage-unavailable" : "invalid-user");
    }
    authenticationserverWipeJsonStrings(user_json);
    cJSON_Delete(user_json);

    if (UNLIKELY(! authenticationserverUserHasRequiredId(&user)))
    {
        if (ts->verbose)
            LOGD("AuthenticationServer: AddNewUser rejected user JSON: user-id-required");
        userDestroy(&user);
        return authenticationserverAddUserRejected(t, l, session, correlation_id, audit_id, "user-id-required");
    }

    audit_id = userGetId(&user);
    size_t export_bytes;
    if (userMeasureExportUpperBound(&user, &export_bytes) != kUserPublicOk || export_bytes > ts->max_user_export_bytes)
    {
        userDestroy(&user);
        return authenticationserverAddUserRejected(t, l, session, correlation_id, audit_id, "user-too-large");
    }
    users_add_result_t add_result = usersAddUserChecked(&ts->store.users, &user);
    userDestroy(&user);

    if (UNLIKELY(add_result != kUsersAddResultOk))
    {
        const char *error = authenticationserverUsersAddResultError(add_result);
        if (add_result == kUsersAddResultStorageUnavailable)
            LOGW("AuthenticationServer: AddNewUser could not initialize account storage");
        else if (add_result == kUsersAddResultInvalidUser)
            /* This private candidate already passed construction; revalidation
             * also performs credential-backend operations that may fail. */
            LOGW("AuthenticationServer: AddNewUser could not revalidate initialized user credentials");
        else if (ts->verbose)
            LOGD("AuthenticationServer: AddNewUser rejected user JSON: %s", error);
        return authenticationserverAddUserRejected(t, l, session, correlation_id, audit_id, error);
    }

    const bool was_dirty = ts->database_dirty;
    if (UNLIKELY(! authenticationserverSaveDatabaseLockedForReason(ts, kAuthenticationServerSaveProducerCreate)))
    {
        LOGW("AuthenticationServer: AddNewUser failed to save database after adding user; rolling back in-memory add");
        usersRollbackUnpublishedLastUserByIdentifier(&ts->store.users, audit_id);
        ts->database_dirty = was_dirty;
        return authenticationserverAddUserRejected(t, l, session, correlation_id, audit_id, "database-save-failed");
    }
    authenticationserverBumpConfigRevision(t);
    ts->database_dirty = false; /* The forced save included this account and prior unsaved changes. */
    authenticationserverAuditRecordProducer(ts->audit,
                                            session != NULL ? session->client_name : NULL,
                                            "AddNewUser",
                                            audit_id,
                                            ts->store.config_revision,
                                            kAuthenticationServerAuditFieldAccount |
                                                kAuthenticationServerAuditFieldCredentials,
                                            NULL);

    static const char ok[] = "user-added";
    LOGI("AuthenticationServer: AddNewUser added a new user and saved the database");
    return authenticationserverCreateResponseFrame(
        l, kAuthenticationServerResponseTypeOk, correlation_id, (const uint8_t *) ok, (uint32_t) (sizeof(ok) - 1U));
}
