#pragma once
#include "api.h"

// 
// dw <------>  networklogger(stdout + file)  <------> up
// 
//

tunnel_t *newLoggerTunnel(node_instance_context_t *instance_info);
void apiLoggerTunnel(tunnel_t *self, char *msg);
tunnel_t *destroyLoggerTunnel(tunnel_t *self);
