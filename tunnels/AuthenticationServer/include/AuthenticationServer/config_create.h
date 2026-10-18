#pragma once

#include "api.h"
#include "edit_token.h"

enum
{
    kAuthenticationServerCreateRequestCap = 32 * 1024,
    kAuthenticationServerCreateAckCap     = 256
};

typedef struct authenticationserver_create_request_s
{
    uint64_t                  id;
    user_prepared_creation_t *candidate;
} authenticationserver_create_request_t;

/* Consumes and wipes the owned request on every result. Only the private prepared
 * account survives success; none of its values borrow the parser tree. */
const char *authenticationserverParseCreate(sbuf_t *, const node_api_call_context_t *,
                                            authenticationserver_create_request_t *);
const char *authenticationserverConfigCreateError(users_add_result_t);
/* State ownership surrounds the collection's bounded insertion and nonfailing
 * commit. The already-reserved ACK is rendered before any account publication. */
const char *authenticationserverApplyCreate(tunnel_t *, authenticationserver_create_request_t *,
                                            const node_api_call_context_t *, sbuf_t *, size_t);
