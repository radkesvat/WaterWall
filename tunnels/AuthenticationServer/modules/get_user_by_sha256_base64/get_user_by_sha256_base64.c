#include "modules/get_user_by_sha256_base64/get_user_by_sha256_base64.h"

#include "loggers/network_logger.h"

sbuf_t *authenticationserverGetUserBySHA256Base64Handle(
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
    tunnel_t     *t,
    line_t       *l,
    const uint8_t *request_data,
    uint32_t      request_data_len)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    uint8_t decoded[BASE64_DECODE_OUT_SIZE(BASE64_ENCODE_OUT_SIZE(SHA256_DIGEST_SIZE))];

    if (request_data_len != BASE64_ENCODE_OUT_SIZE(SHA256_DIGEST_SIZE))
    {
        LOGW("AuthenticationServer: GetUserBySHA256Base64 received invalid %u-byte base64 SHA-256 data",
             (unsigned int) request_data_len);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-sha256-base64");
    }

    int decoded_len = wwBase64Decode((const char *) request_data, request_data_len, decoded);
    if (decoded_len != (int) SHA256_DIGEST_SIZE)
    {
        LOGW("AuthenticationServer: GetUserBySHA256Base64 could not decode request data as a 32-byte SHA-256 digest");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-sha256-base64");
    }

    cJSON *user_json = usersUserToJsonBySHA256(&ts->users, decoded);
    if (user_json == NULL)
    {
        LOGD("AuthenticationServer: GetUserBySHA256Base64 did not find a matching user");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "user-not-found");
    }

    return authenticationserverCreateUserJsonResponseFrame(l, correlation_id, user_json, "GetUserBySHA256Base64");
}
