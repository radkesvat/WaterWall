#pragma once
#include "structure.h"
typedef enum authenticationserver_lookup_e
{
    kAuthLookupPassword,
    kAuthLookupSHA224,
    kAuthLookupSHA256
} authenticationserver_lookup_t;
typedef enum authenticationserver_encoding_e
{
    kAuthLookupRaw,
    kAuthLookupHex,
    kAuthLookupBase64
} authenticationserver_encoding_t;
sbuf_t *authenticationserverLookup(const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize], tunnel_t *t,
                                   line_t *l, const uint8_t *data, uint32_t length, authenticationserver_lookup_t kind,
                                   authenticationserver_encoding_t encoding, const char *operation,
                                   const char *invalid_error);
