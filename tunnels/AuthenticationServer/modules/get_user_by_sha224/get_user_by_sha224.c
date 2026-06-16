#include "modules/get_user_by_sha224/get_user_by_sha224.h"

#include "loggers/network_logger.h"

sbuf_t *authenticationserverGetUserBySHA224Handle(const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                                  tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                                  const uint8_t *request_data, uint32_t request_data_len)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    discard                        session;

    if (UNLIKELY(request_data_len != SHA224_DIGEST_SIZE))
    {
        LOGW("AuthenticationServer: GetUserBySHA224 received invalid %u-byte SHA-224 data",
             (unsigned int) request_data_len);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-sha224");
    }

    cJSON *user_json = usersUserToJsonBySHA224(&ts->store.users, request_data);
    if (user_json == NULL)
    {
        LOGD("AuthenticationServer: GetUserBySHA224 did not find a matching user");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "user-not-found");
    }

    return authenticationserverCreateUserJsonResponseFrame(l, correlation_id, user_json, "GetUserBySHA224");
}
