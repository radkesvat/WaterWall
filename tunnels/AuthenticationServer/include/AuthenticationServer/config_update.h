#pragma once

#include "api.h"
#include "edit_token.h"

enum
{
    kAuthenticationServerUpdateRequestCap = 32 * 1024,
    kAuthenticationServerUpdateAckCap     = 256,
    kAuthenticationServerUpdateGrowthCap  = 1024 * 1024
};

typedef struct authenticationserver_update_request_s
{
    uint64_t                      id, revision;
    uint8_t                       instance_id[16];
    user_config_prepared_patch_t *patch;
} authenticationserver_update_request_t;

/* Consumes the request buffer on every result. The prepared patch owns all
 * selected values and is the only parser state retained on success. */
const char *authenticationserverParseUpdate(sbuf_t *, const node_api_call_context_t *,
                                            authenticationserver_update_request_t *);
const char *authenticationserverConfigUpdateError(users_update_result_t);
/* The ACK is reserved before locking and rendered before the core commit. */
const char *authenticationserverApplyConditionalUpdate(tunnel_t *, authenticationserver_update_request_t *,
                                                       const node_api_call_context_t *, sbuf_t *, size_t);
