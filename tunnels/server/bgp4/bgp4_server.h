#pragma once
#include "api.h"

//
// con <------>  Bgp4Server (simulate bgp4 protocol) <-------> con
//

tunnel_t         *newBgp4Server(node_instance_context_t *instance_info);
api_result_t      apiBgp4Server(tunnel_t *self, const char *msg);
tunnel_t         *destroyBgp4Server(tunnel_t *self);
tunnel_metadata_t getMetadataBgp4Server(void);
