#pragma once
#include "api.h"

//
// con <------>  WolfSSL-server  <------> TLS(con)
//

tunnel_t *        newWolfSSLServer(node_instance_context_t *instance_info);
api_result_t      apiWolfSSLServer(tunnel_t *self,const char *msg);
tunnel_t *        destroyWolfSSLServer(tunnel_t *self);
tunnel_metadata_t getMetadataWolfSSLServer();
