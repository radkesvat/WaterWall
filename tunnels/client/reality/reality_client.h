#pragma once
#include "api.h"

//
// con <------>  Reality-client  <------> TLS(after handshake encryption alg is custom) (con)
//

tunnel_t *        newRealityClient(node_instance_context_t *instance_info);
api_result_t      apiRealityClient(tunnel_t *self, const char *msg);
tunnel_t *        destroyRealityClient(tunnel_t *self);
tunnel_metadata_t getMetadataRealityClient(void);
