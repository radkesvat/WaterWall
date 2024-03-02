#pragma once
#include "api.h"

// 
// con <------>  BoringSSL-server  <------> TLS(con)
// 
//

tunnel_t *newBoringSSLServer(node_instance_context_t *instance_info);
api_result_t apiBoringSSLServer(tunnel_t *self, char *msg);
tunnel_t *destroyBoringSSLServer(tunnel_t *self);
tunnel_metadata_t getMetadataBoringSSLServer();
