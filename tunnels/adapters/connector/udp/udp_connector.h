#pragma once
#include "api.h"

// con <-----\                    /----->   Resolve=>  Udp Associate
// con <------>   UdpConnector    <------>  Resolve=>  Udp Associate
// con <-----/                    \----->   Resolve=>  Udp Associate
//

tunnel_t *        newUdpConnector(node_instance_context_t *instance_info);
api_result_t      apiUdpConnector(tunnel_t *self, const char *msg);
tunnel_t *        destroyUdpConnector(tunnel_t *self);
tunnel_metadata_t getMetadataUdpConnector(void);
