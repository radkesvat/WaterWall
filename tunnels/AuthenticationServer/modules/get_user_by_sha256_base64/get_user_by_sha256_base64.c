#include "modules/get_user_by_sha256_base64/get_user_by_sha256_base64.h"
#include "modules/lookup.h"
sbuf_t *authenticationserverGetUserBySHA256Base64Handle(
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize], tunnel_t *t, line_t *l,
    authenticationserver_session_t *session, const uint8_t *request_data, uint32_t request_data_len)
{
    discard session;
    return authenticationserverLookup(correlation_id,
                                      t,
                                      l,
                                      request_data,
                                      request_data_len,
                                      kAuthLookupSHA256,
                                      kAuthLookupBase64,
                                      "GetUserBySHA256Base64",
                                      "invalid-sha256-base64");
}
