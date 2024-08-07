#pragma once
#include "api.h"

// TunDevice ------>  Layer3Receiver ------>  Layer3Packet

tunnel_t *        newLayer3Receiver(node_instance_context_t *instance_info);
api_result_t      apiLayer3Receiver(tunnel_t *self, const char *msg);
tunnel_t *        destroyLayer3Receiver(tunnel_t *self);
tunnel_metadata_t getMetadataLayer3Receiver(void);
