#pragma once
#include "api.h"

//                                ------->  upload  con
// con <------>  HalfDuplexClient
//                                <------- download con

tunnel_t         *newHalfDuplexClient(node_instance_context_t *instance_info);
api_result_t      apiHalfDuplexClient(tunnel_t *self, const char *msg);
tunnel_t         *destroyHalfDuplexClient(tunnel_t *self);
tunnel_metadata_t getMetadataHalfDuplexClient(void);
