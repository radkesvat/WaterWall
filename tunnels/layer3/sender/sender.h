#pragma once
#include "api.h"

// Layer3Packet  ------>  Layer3Sender ------>  TunDevice

tunnel_t *        newLayer3Sender(node_instance_context_t *instance_info);
api_result_t      apiLayer3Sender(tunnel_t *self, const char *msg);
tunnel_t *        destroyLayer3Sender(tunnel_t *self);
tunnel_metadata_t getMetadataLayer3Sender(void);
