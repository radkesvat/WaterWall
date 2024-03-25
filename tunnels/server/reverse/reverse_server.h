#pragma once
#include "api.h"


// con 1  <------>  Reverse(server)  <------>  con 2



tunnel_t *newReverseServer(node_instance_context_t *instance_info);
api_result_t apiReverseServer(tunnel_t *self, char *msg);
tunnel_t *destroyReverseServer(tunnel_t *self);
tunnel_metadata_t getMetadataReverseServer();
