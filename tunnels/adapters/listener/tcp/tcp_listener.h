#pragma once
#include "api.h"

// user <-----\                 /----->    Tcp con 1
// user <------>  TcpListener  <------>    Tcp con 2
// user <-----/                 \----->    Tcp con 3


tunnel_t         *newTcpListener(node_instance_context_t *instance_info);
api_result_t      apiTcpListener(tunnel_t *self, const char *msg);
tunnel_t         *destroyTcpListener(tunnel_t *self);
tunnel_metadata_t getMetadataTcpListener();
