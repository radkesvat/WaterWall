#include "modules/get_user_by_sha256/get_user_by_sha256.h"
#include "modules/lookup.h"
sbuf_t *authenticationserverGetUserBySHA256Handle(const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                                  tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                                  const uint8_t *request_data, uint32_t request_data_len)
{
    discard session;
    return authenticationserverLookup(correlation_id,
                                      t,
                                      l,
                                      request_data,
                                      request_data_len,
                                      kAuthLookupSHA256,
                                      kAuthLookupRaw,
                                      "GetUserBySHA256",
                                      "invalid-sha256");
}
