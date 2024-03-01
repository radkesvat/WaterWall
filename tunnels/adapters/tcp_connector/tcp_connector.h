#pragma once
#include "api.h"


// con <-----\                /----->  Resolve=>  TCP Connect || Udp Associate
// con <------>  TcpConnector   <------>  Resolve=>  TCP Connect || Udp Associate
// con <-----/                \----->  Resolve=>  TCP Connect || Udp Associate
//

#define NODE_TCP_LISTINER

tunnel_t *newTcpConnector(node_instance_context_t *instance_info);
void apiTcpConnector(tunnel_t *self, char *msg);
tunnel_t *destroyTcpConnector(tunnel_t *self);
