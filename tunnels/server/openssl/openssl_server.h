#pragma once
#include "api.h"
#include "hv/hssl.h"

// 
// con <------>  OpenSSL-server  <------> TLS(con)
// 
//

tunnel_t *newOpenSSLServer(node_instance_context_t *instance_info);
api_result_t apiOpenSSLServer(tunnel_t *self, char *msg);
tunnel_t *destroyOpenSSLServer(tunnel_t *self);
tunnel_metadata_t getMetadataOpenSSLServer();
