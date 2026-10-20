#pragma once
#include "structure.h"

typedef struct authenticationserver_module_s
{
    uint8_t                                request_type;
    const char                            *name;
    authenticationserver_module_handler_fn handler;
    bool                                   public_access, require_stats_push, require_user_pull, require_user_write;
    bool                                   mutates_store, write_lock;
} authenticationserver_module_t;

const authenticationserver_module_t *authenticationserverFindModule(uint8_t request_type);
sbuf_t                              *authenticationserverDispatchModule(const authenticationserver_module_t *module,
                                                                        const uint8_t correlation_id[kAuthenticationServerCorrelationIdSize],
                                                                        tunnel_t *t, line_t *l, authenticationserver_session_t *session,
                                                                        const uint8_t *request_data, uint32_t request_data_len);
