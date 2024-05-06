#pragma once
#include "api.h"

//                                          |  <------> con
//                                          |
// con <------>  Reality-server  <------> auth <------> dest
//

tunnel_t         *newRealityServer(node_instance_context_t *instance_info);
api_result_t      apiRealityServer(tunnel_t *self, const char *msg);
tunnel_t         *destroyRealityServer(tunnel_t *self);
tunnel_metadata_t getMetadataRealityServer();
