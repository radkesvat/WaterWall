#include "modules/get_user_by_sha224_hex/get_user_by_sha224_hex.h"

#include "loggers/network_logger.h"

static bool authenticationserverParseSHA224Hex(const uint8_t *hex, uint32_t hex_len, uint8_t out[SHA224_DIGEST_SIZE])
{
    return asciiHexDecodeBytes(hex, hex_len, out, SHA224_DIGEST_SIZE);
}

sbuf_t *authenticationserverGetUserBySHA224HexHandle(
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize], tunnel_t *t, line_t *l,
    authenticationserver_session_t *session, const uint8_t *request_data, uint32_t request_data_len)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    uint8_t                        sha224[SHA224_DIGEST_SIZE];
    discard                        session;

    if (UNLIKELY(! authenticationserverParseSHA224Hex(request_data, request_data_len, sha224)))
    {
        LOGW("AuthenticationServer: GetUserBySHA224Hex received invalid %u-byte SHA-224 hex data",
             (unsigned int) request_data_len);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-sha224-hex");
    }

    cJSON *user_json = usersUserToJsonBySHA224(&ts->store.users, sha224);
    if (user_json == NULL)
    {
        LOGD("AuthenticationServer: GetUserBySHA224Hex did not find a matching user");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "user-not-found");
    }

    return authenticationserverCreateUserJsonResponseFrame(l, correlation_id, user_json, "GetUserBySHA224Hex");
}
