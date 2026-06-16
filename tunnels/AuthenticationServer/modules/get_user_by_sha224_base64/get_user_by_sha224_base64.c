#include "modules/get_user_by_sha224_base64/get_user_by_sha224_base64.h"

#include "loggers/network_logger.h"

sbuf_t *authenticationserverGetUserBySHA224Base64Handle(
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize], tunnel_t *t, line_t *l,
    authenticationserver_session_t *session, const uint8_t *request_data, uint32_t request_data_len)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    uint8_t                        decoded[BASE64_DECODE_OUT_SIZE(BASE64_ENCODE_OUT_SIZE(SHA224_DIGEST_SIZE))];
    discard                        session;

    if (UNLIKELY(request_data_len != BASE64_ENCODE_OUT_SIZE(SHA224_DIGEST_SIZE)))
    {
        LOGW("AuthenticationServer: GetUserBySHA224Base64 received invalid %u-byte base64 SHA-224 data",
             (unsigned int) request_data_len);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-sha224-base64");
    }

    int decoded_len = wwBase64Decode((const char *) request_data, request_data_len, decoded);
    if (UNLIKELY(decoded_len != (int) SHA224_DIGEST_SIZE))
    {
        LOGW("AuthenticationServer: GetUserBySHA224Base64 could not decode request data as a 28-byte SHA-224 digest");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-sha224-base64");
    }

    cJSON *user_json = usersUserToJsonBySHA224(&ts->store.users, decoded);
    if (user_json == NULL)
    {
        LOGD("AuthenticationServer: GetUserBySHA224Base64 did not find a matching user");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "user-not-found");
    }

    return authenticationserverCreateUserJsonResponseFrame(l, correlation_id, user_json, "GetUserBySHA224Base64");
}
