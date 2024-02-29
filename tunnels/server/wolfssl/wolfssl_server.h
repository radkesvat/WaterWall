#pragma once
#include "api.h"

// 
// con <------>  WolfSSL-server  <------> TLS(con)
// 
//

tunnel_t *newWolfSSLServer(node_instance_context_t *instance_info);
void apiWolfSSLServer(tunnel_t *self, char *msg);
tunnel_t *destroyWolfSSLServer(tunnel_t *self);
