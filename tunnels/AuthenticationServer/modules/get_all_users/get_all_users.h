#pragma once

#include "structure.h"

sbuf_t *authenticationserverGetAllUsersHandle(
    const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
    tunnel_t     *t,
    line_t       *l,
    const uint8_t *request_data,
    uint32_t      request_data_len);
