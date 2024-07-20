#pragma once
#include "api.h"

// con <------>  
// con <------>  MuxClient  <-------> con
// con <------>  

tunnel_t         *newMuxClient(node_instance_context_t *instance_info);
api_result_t      apiMuxClient(tunnel_t *self, const char *msg);
tunnel_t         *destroyMuxClient(tunnel_t *self);
tunnel_metadata_t getMetadataMuxClient(void);
