#pragma once
#include "api.h"

// 
// con <------>  WireGuard  <-------> con
// 

tunnel_t *newWireGuard(node_instance_context_t *instance_info);
api_result_t apiWireGuard(tunnel_t *self, const char *msg);
tunnel_t *destroyWireGuard(tunnel_t *self);
tunnel_metadata_t getMetadataWireGuard();



