#pragma once
#include "api.h"

// user <-----\                /----->   (Tcp|Udp) listener
// user <------>  Listener    <------>   (Tcp|Udp) listener
// user <-----/                \----->   (Tcp|Udp) listener
//

tunnel_t *        newListener(node_instance_context_t *instance_info);
api_result_t      apiListener(tunnel_t *self, const char *msg);
tunnel_t *        destroyListener(tunnel_t *self);
tunnel_metadata_t getMetadataListener(void);
