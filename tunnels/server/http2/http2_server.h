#pragma once
#include "api.h"

//
// con <------>  http2-server  <------> http2 stream (con)
//

tunnel_t *        newHttp2Server(node_instance_context_t *instance_info);
api_result_t      apiHttp2Server(tunnel_t *self, const char *msg);
tunnel_t *        destroyHttp2Server(tunnel_t *self);
tunnel_metadata_t getMetadataHttp2Server(void);
