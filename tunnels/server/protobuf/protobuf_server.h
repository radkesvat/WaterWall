#pragma once
#include "api.h"

// 
// con <------> encode/decode (protocolbuffers)  <------> con
// 
//

tunnel_t *newProtoBufServer(node_instance_context_t *instance_info);
api_result_t apiProtoBufServer(tunnel_t *self, char *msg);
tunnel_t *destroyProtoBufServer(tunnel_t *self);
tunnel_metadata_t getMetadataProtoBufServer();
