#include "modules/authenticate/authenticate.h"

#include "loggers/network_logger.h"

sbuf_t *authenticationserverAuthenticateHandle(const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                               tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                               const uint8_t *request_data, uint32_t request_data_len)
{
    discard session;

    if (request_data_len == 0)
    {
        LOGW("AuthenticationServer: Authenticate received an empty JSON payload");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-auth-request");
    }

    cJSON *json = cJSON_ParseWithLength((const char *) request_data, request_data_len);
    if (! cJSON_IsObject(json))
    {
        cJSON_Delete(json);
        LOGW("AuthenticationServer: Authenticate received malformed JSON");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-auth-request");
    }

    const cJSON *name_json   = cJSON_GetObjectItemCaseSensitive(json, "name");
    const cJSON *secret_json = cJSON_GetObjectItemCaseSensitive(json, "secret");
    if (! cJSON_IsString(name_json) || name_json->valuestring == NULL || name_json->valuestring[0] == '\0' ||
        ! cJSON_IsString(secret_json) || secret_json->valuestring == NULL || secret_json->valuestring[0] == '\0')
    {
        cJSON_Delete(json);
        LOGW("AuthenticationServer: Authenticate request is missing name or secret");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-auth-request");
    }

    authenticationserver_session_t *new_session =
        authenticationserverSessionCreate(t, name_json->valuestring, secret_json->valuestring);
    cJSON_Delete(json);

    if (new_session == NULL)
    {
        LOGW("AuthenticationServer: Authenticate rejected client credentials");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "authentication-failed");
    }

    return authenticationserverCreateResponseFrame(l,
                                                   kAuthenticationServerResponseTypeSession,
                                                   correlation_id,
                                                   new_session->token,
                                                   kAuthenticationServerSessionTokenSize);
}
