#include "modules/get_user_by_password/get_user_by_password.h"

#include "loggers/network_logger.h"

static char *authenticationserverPasswordFromPayload(const uint8_t *request_data, uint32_t request_data_len)
{
    if (UNLIKELY(request_data_len == 0 || request_data_len > kAuthenticationServerMaxPasswordLength))
    {
        return NULL;
    }

    for (uint32_t i = 0; i < request_data_len; ++i)
    {
        if (UNLIKELY(request_data[i] == '\0'))
        {
            return NULL;
        }
    }

    char *password = memoryAllocate((size_t) request_data_len + 1U);
    if (UNLIKELY(password == NULL))
    {
        return NULL;
    }

    memoryCopy(password, request_data, request_data_len);
    password[request_data_len] = '\0';
    return password;
}

sbuf_t *authenticationserverGetUserByPasswordHandle(
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize], tunnel_t *t, line_t *l,
    authenticationserver_session_t *session, const uint8_t *request_data, uint32_t request_data_len)
{
    authenticationserver_tstate_t *ts       = tunnelGetState(t);
    char                          *password = authenticationserverPasswordFromPayload(request_data, request_data_len);
    discard                        session;

    if (UNLIKELY(password == NULL))
    {
        LOGW("AuthenticationServer: GetUserByPassword received invalid %u-byte password data",
             (unsigned int) request_data_len);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-password");
    }

    cJSON *user_json = usersUserToJsonByPassword(&ts->store.users, password);
    wCryptoZero(password, request_data_len);
    memoryFree(password);

    if (user_json == NULL)
    {
        LOGD("AuthenticationServer: GetUserByPassword did not find a matching user");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "user-not-found");
    }

    return authenticationserverCreateUserJsonResponseFrame(l, correlation_id, user_json, "GetUserByPassword");
}
