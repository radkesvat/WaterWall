#pragma once

#include "api.h"
#include "edit_token.h"

enum
{
    kAuthenticationServerPasswordRequestCap = 32 * 1024,
    kAuthenticationServerPasswordAckCap     = 256
};

typedef struct authenticationserver_password_request_s
{
    uint64_t                         id, revision;
    uint8_t                          instance_id[16];
    user_prepared_password_change_t *password;
} authenticationserver_password_request_t;

/* Consumes and wipes the owned request on every result. The retained prepared
 * credential material owns every byte; it never borrows the JSON tree. */
const char *authenticationserverParsePasswordChange(sbuf_t *, const node_api_call_context_t *,
                                                    authenticationserver_password_request_t *);
const char *authenticationserverPasswordChangeError(users_password_result_t);
/* The ACK is reserved before locking and rendered before the irreversible
 * credentials/index commit. No response work follows a successful mutation. */
const char *authenticationserverApplyConditionalPasswordChange(tunnel_t *, authenticationserver_password_request_t *,
                                                               const node_api_call_context_t *, sbuf_t *, size_t);
