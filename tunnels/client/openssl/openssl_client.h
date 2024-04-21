#pragma once
#include "api.h"

//
// con <------>  OpenSSL-client  <------> TLS(con)
//

tunnel_t *        newOpenSSLClient(node_instance_context_t *instance_info);
api_result_t      apiOpenSSLClient(tunnel_t *self, const char *msg);
tunnel_t *        destroyOpenSSLClient(tunnel_t *self);
tunnel_metadata_t getMetadataOpenSSLClient();
