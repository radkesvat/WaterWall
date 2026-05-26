#include "modules/get_all_users/get_all_users.h"

#include "loggers/network_logger.h"

sbuf_t *authenticationserverGetAllUsersHandle(
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
    tunnel_t     *t,
    line_t       *l,
    const uint8_t *request_data,
    uint32_t      request_data_len)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    discard request_data;

    if (request_data_len != 0)
    {
        LOGW("AuthenticationServer: GetAllUsers received unexpected %u-byte request data",
             (unsigned int) request_data_len);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-get-all-users-request");
    }

    cJSON *users_json = usersToJson(&ts->users);
    if (users_json == NULL)
    {
        LOGW("AuthenticationServer: GetAllUsers failed to export users database");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "users-json-export-failed");
    }

    char *users_json_text = cJSON_PrintUnformatted(users_json);
    cJSON_Delete(users_json);

    if (users_json_text == NULL)
    {
        LOGW("AuthenticationServer: GetAllUsers failed to serialize users database");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "users-json-serialize-failed");
    }

    sbuf_t *response = authenticationserverCreateResponseFrame(l,
                                                               kAuthenticationServerResponseTypeUsers,
                                                               correlation_id,
                                                               (const uint8_t *) users_json_text,
                                                               (uint32_t) stringLength(users_json_text));
    cJSON_free(users_json_text);
    return response;
}
