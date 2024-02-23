#pragma once
#include "api.h"


// con <-----\                /----->  Resolve=>  TCP Connect || Udp Associate
// con <------>  Connector   <------>  Resolve=>  TCP Connect || Udp Associate
// con <-----/                \----->  Resolve=>  TCP Connect || Udp Associate
//

#define NODE_TCP_LISTINER

tunnel_t *newConnector(node_instance_context_t *instance_info);
void apiConnector(tunnel_t *self, char *msg);
tunnel_t *destroyConnector(tunnel_t *self);
