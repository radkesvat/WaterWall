#pragma once
#include "api.h"

// Layer3Packet <------>  override (source or dest) ip   <------>  Layer3Packet

tunnel_t *        newLayer3IpOverrider(node_instance_context_t *instance_info);
api_result_t      apiLayer3IpOverrider(tunnel_t *self, const char *msg);
tunnel_t *        destroyLayer3IpOverrider(tunnel_t *self);
tunnel_metadata_t getMetadataLayer3IpOverrider(void);
