#include "modules/get_user_by_sha256/get_user_by_sha256.h"

#include "loggers/network_logger.h"

sbuf_t *authenticationserverGetUserBySHA256Handle(const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                                  tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                                  const uint8_t *request_data, uint32_t request_data_len)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    discard                        session;

    if (UNLIKELY(request_data_len != SHA256_DIGEST_SIZE))
    {
        LOGW("AuthenticationServer: GetUserBySHA256 received invalid %u-byte SHA-256 data",
             (unsigned int) request_data_len);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-sha256");
    }

    cJSON *user_json = usersUserToJsonBySHA256(&ts->store.users, request_data);
    if (user_json == NULL)
    {
        LOGD("AuthenticationServer: GetUserBySHA256 did not find a matching user");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "user-not-found");
    }

    return authenticationserverCreateUserJsonResponseFrame(l, correlation_id, user_json, "GetUserBySHA256");
}
