#pragma once
#include "api.h"

// con <-----\                    /----->  Resolve=>  Udp Associate
// con <------>   Udponnector    <------>  Resolve=>  Udp Associate
// con <-----/                    \----->  Resolve=>  Udp Associate
//

tunnel_t *        newUdponnector(node_instance_context_t *instance_info);
api_result_t      apiUdponnector(tunnel_t *self, const char *msg);
tunnel_t *        destroyUdponnector(tunnel_t *self);
tunnel_metadata_t getMetadataUdponnector();
