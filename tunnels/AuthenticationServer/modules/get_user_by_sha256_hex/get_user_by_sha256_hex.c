#include "modules/get_user_by_sha256_hex/get_user_by_sha256_hex.h"

#include "loggers/network_logger.h"

static int authenticationserverHexValue(uint8_t c)
{
    if (c >= '0' && c <= '9')
    {
        return (int) (c - '0');
    }
    if (c >= 'a' && c <= 'f')
    {
        return (int) (c - 'a') + 10;
    }
    if (c >= 'A' && c <= 'F')
    {
        return (int) (c - 'A') + 10;
    }
    return -1;
}

static bool authenticationserverParseSHA256Hex(const uint8_t *hex, uint32_t hex_len, uint8_t out[SHA256_DIGEST_SIZE])
{
    if (UNLIKELY(hex_len != SHA256_DIGEST_SIZE * 2U))
    {
        return false;
    }

    for (uint32_t i = 0; i < SHA256_DIGEST_SIZE; ++i)
    {
        int hi = authenticationserverHexValue(hex[i * 2U]);
        int lo = authenticationserverHexValue(hex[i * 2U + 1U]);
        if (UNLIKELY(hi < 0 || lo < 0))
        {
            return false;
        }
        out[i] = (uint8_t) ((hi << 4U) | lo);
    }

    return true;
}

sbuf_t *authenticationserverGetUserBySHA256HexHandle(
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize], tunnel_t *t, line_t *l,
    authenticationserver_session_t *session, const uint8_t *request_data, uint32_t request_data_len)
{
    authenticationserver_tstate_t *ts = tunnelGetState(t);
    uint8_t                        sha256[SHA256_DIGEST_SIZE];
    discard                        session;

    if (UNLIKELY(! authenticationserverParseSHA256Hex(request_data, request_data_len, sha256)))
    {
        LOGW("AuthenticationServer: GetUserBySHA256Hex received invalid %u-byte SHA-256 hex data",
             (unsigned int) request_data_len);
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "invalid-sha256-hex");
    }

    cJSON *user_json = usersUserToJsonBySHA256(&ts->store.users, sha256);
    if (user_json == NULL)
    {
        LOGD("AuthenticationServer: GetUserBySHA256Hex did not find a matching user");
        return authenticationserverCreateErrorResponseFrame(l, correlation_id, "user-not-found");
    }

    return authenticationserverCreateUserJsonResponseFrame(l, correlation_id, user_json, "GetUserBySHA256Hex");
}
