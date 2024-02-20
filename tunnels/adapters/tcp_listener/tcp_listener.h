#pragma once
#include "api.h"
#include "utils/jsonutils.h"
//
// user <-----\               /----->    con 1
// user <------>  TcpListener  <------>  con 2
// user <-----/               \----->    con 3
//

#define NODE_TCP_LISTINER

tunnel_t *newTcpListener(node_instance_context_t *instance_info);
void apiTcpListener(tunnel_t *self, char *msg);
tunnel_t *destroyTcpListener(tunnel_t *self);
