#pragma once
#include "api.h"

// 
// con <------>  http2-server  <------> http2 stream (con)
// 
//

tunnel_t *newHttp2Client(node_instance_context_t *instance_info);
api_result_t apiHttp2Client(tunnel_t *self, char *msg);
tunnel_t *destroyHttp2Client(tunnel_t *self);
tunnel_metadata_t getMetadataHttp2Client();



