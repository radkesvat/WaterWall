#pragma once
#include "api.h"

// 
//      CaptureDevice
// 

//  this node will not join a chain , it will be used by other nodes (if they accept a device)

tunnel_t *        newCaptureDevice(node_instance_context_t *instance_info);
api_result_t      apiCaptureDevice(tunnel_t *self, const char *msg);
tunnel_t *        destroyCaptureDevice(tunnel_t *self);
tunnel_metadata_t getMetadataCaptureDevice(void);
