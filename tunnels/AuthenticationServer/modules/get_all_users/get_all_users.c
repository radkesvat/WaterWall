#include "modules/get_all_users/get_all_users.h"

#include "loggers/network_logger.h"

sbuf_t *authenticationserverGetAllUsersHandle(const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                              tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                              const uint8_t *request_data, uint32_t request_data_len)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    discard                        request_data;

    if (UNLIKELY(request_data_len != 0))
    {
        LOGW("AuthenticationServer: GetAllUsers received unexpected %u-byte request data",
             (unsigned int) request_data_len);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-get-all-users-request");
    }

    cJSON *users_json = usersToJson(&ts->store.users);
    if (UNLIKELY(users_json == NULL))
    {
        LOGW("AuthenticationServer: GetAllUsers failed to export users database");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "users-json-export-failed");
    }

    char *users_json_text = cJSON_PrintUnformatted(users_json);
    if (UNLIKELY(users_json_text == NULL))
    {
        cJSON_Delete(users_json);
        LOGW("AuthenticationServer: GetAllUsers failed to serialize users database");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "users-json-serialize-failed");
    }

    const size_t users_json_text_len = stringLength(users_json_text);
    if (UNLIKELY(users_json_text_len >
                 kAuthenticationServerMaxResponsePayload - kAuthenticationServerResponseHeaderSize))
    {
        cJSON_Delete(users_json);
        cJSON_free(users_json_text);
        LOGW("AuthenticationServer: GetAllUsers response is too large");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "response-too-large");
    }

    // Dispatcher reaches this non-public module only with an authenticated session.
    if (UNLIKELY(! authenticationserverSessionReplaceBaselineFromUsers(
            session, &ts->store.users, ts->store.config_revision, ts->store.stats_revision)))
    {
        LOGW("AuthenticationServer: GetAllUsers failed to refresh session baseline");
        cJSON_Delete(users_json);
        cJSON_free(users_json_text);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "session-baseline-update-failed");
    }

    cJSON_Delete(users_json);

    sbuf_t *response = authenticationserverCreateResponseFrame(l,
                                                               kAuthenticationServerResponseTypeUsers,
                                                               correlation_id,
                                                               (const uint8_t *) users_json_text,
                                                               (uint32_t) users_json_text_len);
    cJSON_free(users_json_text);
    return response;
}
