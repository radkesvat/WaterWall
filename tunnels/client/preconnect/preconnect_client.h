#pragma once
#include "api.h"

// 
// con <------>  PreConnectClient <-------> con (established ahead of time)
// 
//

tunnel_t *newPreConnectClient(node_instance_context_t *instance_info);
api_result_t apiPreConnectClient(tunnel_t *self, char *msg);
tunnel_t *destroyPreConnectClient(tunnel_t *self);
tunnel_metadata_t getMetadataPreConnectClient();



