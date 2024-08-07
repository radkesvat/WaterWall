#pragma once
#include "api.h"

// 
//      TunDevice
// 

//  this node will not join a chain , it will be used by other nodes (if they accept a device)

tunnel_t *        newTunDevice(node_instance_context_t *instance_info);
api_result_t      apiTunDevice(tunnel_t *self, const char *msg);
tunnel_t *        destroyTunDevice(tunnel_t *self);
tunnel_metadata_t getMetadataTunDevice(void);
