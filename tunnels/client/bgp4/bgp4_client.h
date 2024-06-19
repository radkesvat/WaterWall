#pragma once
#include "api.h"

//
// con <------>  Bgp4Client (simulate bgp4 protocol) <-------> con
//

tunnel_t         *newBgp4Client(node_instance_context_t *instance_info);
api_result_t      apiBgp4Client(tunnel_t *self, const char *msg);
tunnel_t         *destroyBgp4Client(tunnel_t *self);
tunnel_metadata_t getMetadataBgp4Client(void);
