#pragma once
#include "api.h"

// con <-----\                    /----->  Resolve=>  TCP Connect
// con <------>   TcpConnector   <------>  Resolve=>  TCP Connect
// con <-----/                    \----->  Resolve=>  TCP Connect


tunnel_t *        newTcpConnector(node_instance_context_t *instance_info);
api_result_t      apiTcpConnector(tunnel_t *self, const char *msg);
tunnel_t *        destroyTcpConnector(tunnel_t *self);
tunnel_metadata_t getMetadataTcpConnector(void);
