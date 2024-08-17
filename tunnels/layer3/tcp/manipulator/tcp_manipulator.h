#pragma once
#include "api.h"

// Layer3Packet ------>  manipulate tcp header   ------>  Layer3Packet

tunnel_t *        newLayer3TcpManipulator(node_instance_context_t *instance_info);
api_result_t      apiLayer3TcpManipulator(tunnel_t *self, const char *msg);
tunnel_t *        destroyLayer3TcpManipulator(tunnel_t *self);
tunnel_metadata_t getMetadataLayer3TcpManipulator(void);
