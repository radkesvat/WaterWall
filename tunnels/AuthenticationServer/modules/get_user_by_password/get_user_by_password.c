#include "modules/get_user_by_password/get_user_by_password.h"
#include "modules/lookup.h"
sbuf_t *authenticationserverGetUserByPasswordHandle(
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize], tunnel_t *t, line_t *l,
    authenticationserver_session_t *session, const uint8_t *request_data, uint32_t request_data_len)
{
    discard session;
    return authenticationserverLookup(correlation_id,
                                      t,
                                      l,
                                      request_data,
                                      request_data_len,
                                      kAuthLookupPassword,
                                      kAuthLookupRaw,
                                      "GetUserByPassword",
                                      "invalid-password");
}
