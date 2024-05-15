#pragma once
#include "api.h"

// con <------>  Bridge(pair 1)   <------>  Bridge(pair 2)  <------>  con

tunnel_t *        newBridge(node_instance_context_t *instance_info);
api_result_t      apiBridge(tunnel_t *self, const char *msg);
tunnel_t *        destroyBridge(tunnel_t *self);
tunnel_metadata_t getMetadataBridge(void);
