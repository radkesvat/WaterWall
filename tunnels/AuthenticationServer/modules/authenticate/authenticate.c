#include "modules/authenticate/authenticate.h"
#include "../../../Internals/AuthenticationCommon/credentials.h"
#include "node_builder/config_lexical.h"

#include "loggers/network_logger.h"

sbuf_t *authenticationserverAuthenticateHandle(const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                               tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                               const uint8_t *request_data, uint32_t request_data_len)
{
    discard session;

    if (UNLIKELY(request_data_len == 0 || request_data_len > kAuthenticationAuthenticateDataLimit))
    {
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-auth-request");
    }

    cJSON *json = configLexicalParseBoundedQuiet((const char *) request_data, request_data_len, 2, 8);
    if (UNLIKELY(! cJSON_IsObject(json)))
    {
        cJSON_Delete(json);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-auth-request");
    }

    const cJSON *field = NULL;
    cJSON_ArrayForEach(field, json)
    {
        if (stringCompare(field->string, "name") != 0 && stringCompare(field->string, "secret") != 0 &&
            stringCompare(field->string, "epoch") != 0)
        {
            cJSON_Delete(json);
            return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-auth-request");
        }
    }

    const cJSON *name_json   = cJSON_GetObjectItemCaseSensitive(json, "name");
    const cJSON *secret_json = cJSON_GetObjectItemCaseSensitive(json, "secret");
    if (UNLIKELY(! cJSON_IsString(name_json) || name_json->valuestring == NULL || name_json->valuestring[0] == '\0' ||
                 ! cJSON_IsString(secret_json) || secret_json->valuestring == NULL ||
                 secret_json->valuestring[0] == '\0'))
    {
        cJSON_Delete(json);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-auth-request");
    }

    const cJSON *epoch_json = cJSON_GetObjectItemCaseSensitive(json, "epoch");
    uint8_t      decoded[32];
    if (epoch_json != NULL &&
        (! cJSON_IsString(epoch_json) || epoch_json->valuestring == NULL ||
         stringLength(epoch_json->valuestring) != 64 ||
         ! asciiHexDecodeBytes((const uint8_t *) epoch_json->valuestring, 64, decoded, sizeof(decoded))))
    {
        cJSON_Delete(json);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-auth-request");
    }
    const char                     *error;
    authenticationserver_session_t *new_session =
        authenticationserverSessionCreate(t,
                                          name_json->valuestring,
                                          secret_json->valuestring,
                                          epoch_json != NULL ? (const uint8_t *) epoch_json->valuestring : NULL,
                                          &error);
    cJSON_Delete(json);

    if (UNLIKELY(new_session == NULL))
    {
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, error);
    }

    uint8_t response[128];
    memoryCopy(response, new_session->token, 64);
    memoryCopy(response + 64, new_session->accounting_epoch, 64);
    return authenticationserverCreateResponseFrame(
        l, kAuthenticationServerResponseTypeSession, correlation_id, response, sizeof(response));
}
