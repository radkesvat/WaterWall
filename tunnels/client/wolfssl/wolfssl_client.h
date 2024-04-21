#pragma once
#include "api.h"

//
// con <------>  WolfSSL-client  <------> TLS(con)
//

tunnel_t *        newWolfSSLClient(node_instance_context_t *instance_info);
api_result_t      apiWolfSSLClient(tunnel_t *self,const char *msg);
tunnel_t *        destroyWolfSSLClient(tunnel_t *self);
tunnel_metadata_t getMetadataWolfSSLClient();
