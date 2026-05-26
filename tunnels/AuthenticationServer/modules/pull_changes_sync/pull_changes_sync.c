#include "modules/pull_changes_sync/pull_changes_sync.h"

#include "loggers/network_logger.h"

sbuf_t *authenticationserverPullChangesSyncHandle(
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
    tunnel_t     *t,
    line_t       *l,
    const uint8_t *request_data,
    uint32_t      request_data_len)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);

    if (request_data_len == 0)
    {
        LOGW("AuthenticationServer: PullChangesSync received an empty JSON payload");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-pull-changes-sync-request");
    }

    cJSON *client_users = cJSON_ParseWithLength((const char *) request_data, request_data_len);
    if (client_users == NULL)
    {
        LOGW("AuthenticationServer: PullChangesSync received malformed JSON");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-pull-changes-sync-request");
    }
    if (! cJSON_IsArray(client_users))
    {
        LOGW("AuthenticationServer: PullChangesSync JSON payload is not an array");
        cJSON_Delete(client_users);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-pull-changes-sync-request");
    }

    cJSON *changed_users = usersPullChangesJson(&ts->users, client_users);
    cJSON_Delete(client_users);
    if (changed_users == NULL)
    {
        LOGW("AuthenticationServer: PullChangesSync failed to build changed users array");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "pull-changes-sync-failed");
    }

    char *changed_users_text = cJSON_PrintUnformatted(changed_users);
    cJSON_Delete(changed_users);
    if (changed_users_text == NULL)
    {
        LOGW("AuthenticationServer: PullChangesSync failed to serialize changed users array");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "pull-changes-sync-serialize-failed");
    }

    sbuf_t *response = authenticationserverCreateResponseFrame(l,
                                                               kAuthenticationServerResponseTypeSyncUsers,
                                                               correlation_id,
                                                               (const uint8_t *) changed_users_text,
                                                               (uint32_t) stringLength(changed_users_text));
    cJSON_free(changed_users_text);
    return response;
}
