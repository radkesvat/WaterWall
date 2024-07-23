#pragma once
#include "api.h"

//                            <------> con 
//   con <-------> MuxServer  <------> con 
//                            <------> con 

tunnel_t         *newMuxServer(node_instance_context_t *instance_info);
api_result_t      apiMuxServer(tunnel_t *self, const char *msg);
tunnel_t         *destroyMuxServer(tunnel_t *self);
tunnel_metadata_t getMetadataMuxServer(void);
