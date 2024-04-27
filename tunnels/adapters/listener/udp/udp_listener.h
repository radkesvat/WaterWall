#pragma once
#include "api.h"

// user <-----\                 /----->   simulated con 1
// user <------>  UdpListener  <------>   simulated con 2
// user <-----/                 \----->   simulated con 3
//


tunnel_t *        newUdpListener(node_instance_context_t *instance_info);
api_result_t      apiUdpListener(tunnel_t *self, const char *msg);
tunnel_t *        destroyUdpListener(tunnel_t *self);
tunnel_metadata_t getMetadataUdpListener();
