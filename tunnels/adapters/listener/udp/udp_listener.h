#pragma once
#include "api.h"

// user <-----\                 /----->   simulated Udp con 1
// user <------>  UdpListener  <------>   simulated Udp con 2
// user <-----/                 \----->   simulated Udp con 3
//


tunnel_t *        newUdpListener(node_instance_context_t *instance_info);
api_result_t      apiUdpListener(tunnel_t *self, const char *msg);
tunnel_t *        destroyUdpListener(tunnel_t *self);
tunnel_metadata_t getMetadataUdpListener(void);
