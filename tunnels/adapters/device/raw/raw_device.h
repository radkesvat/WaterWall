#pragma once
#include "api.h"

// 
//      RawDevice
// 

//  this node will not join a chain , it will be used by other nodes (if they accept a device)

tunnel_t *        newRawDevice(node_instance_context_t *instance_info);
api_result_t      apiRawDevice(tunnel_t *self, const char *msg);
tunnel_t *        destroyRawDevice(tunnel_t *self);
tunnel_metadata_t getMetadataRawDevice(void);
