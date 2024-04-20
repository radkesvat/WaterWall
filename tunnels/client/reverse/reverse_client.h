#pragma once
#include "api.h"


// con 2  <------>  Reverse(Client)  <------>  con 1



tunnel_t *newReverseClient(node_instance_context_t *instance_info);
api_result_t apiReverseClient(tunnel_t *self, const char *msg);
tunnel_t *destroyReverseClient(tunnel_t *self);
tunnel_metadata_t getMetadataReverseClient();
