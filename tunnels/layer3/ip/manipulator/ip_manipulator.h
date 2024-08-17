#pragma once
#include "api.h"

// Layer3Packet ------>  manipulate ip header   ------>  Layer3Packet

tunnel_t *        newLayer3IPManipulator(node_instance_context_t *instance_info);
api_result_t      apiLayer3IPManipulator(tunnel_t *self, const char *msg);
tunnel_t *        destroyLayer3IPManipulator(tunnel_t *self);
tunnel_metadata_t getMetadataLayer3IPManipulator(void);
