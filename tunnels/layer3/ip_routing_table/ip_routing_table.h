#pragma once
#include "api.h"
                                       
// Layer3Packet <------>  if(ip == rule)  <------> Layer3Packet

tunnel_t *        newLayer3IpRoutingTable(node_instance_context_t *instance_info);
api_result_t      apiLayer3IpRoutingTable(tunnel_t *self, const char *msg);
tunnel_t *        destroyLayer3IpRoutingTable(tunnel_t *self);
tunnel_metadata_t getMetadataLayer3IpRoutingTable(void);
