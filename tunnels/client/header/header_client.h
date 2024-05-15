#pragma once
#include "api.h"

// 
// con <------>  HeaderClient (encapsulate(data)) <-------> con
// 

tunnel_t *newHeaderClient(node_instance_context_t *instance_info);
api_result_t apiHeaderClient(tunnel_t *self, const char *msg);
tunnel_t *destroyHeaderClient(tunnel_t *self);
tunnel_metadata_t getMetadataHeaderClient(void);



