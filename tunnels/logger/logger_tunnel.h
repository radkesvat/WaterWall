#pragma once
#include "api.h"

//
// dw <------>  networklogger  <------> up
//

tunnel_t *        newLoggerTunnel(node_instance_context_t *instance_info);
api_result_t      apiLoggerTunnel(tunnel_t *self, const char *msg);
tunnel_t *        destroyLoggerTunnel(tunnel_t *self);
tunnel_metadata_t getMetadataLoggerTunnel(void);
