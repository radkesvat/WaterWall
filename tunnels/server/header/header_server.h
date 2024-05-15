#pragma once
#include "api.h"

//
// con <------>  HeaderServer (decapsulate(data)) <-------> con
//

tunnel_t *        newHeaderServer(node_instance_context_t *instance_info);
api_result_t      apiHeaderServer(tunnel_t *self,const char *msg);
tunnel_t *        destroyHeaderServer(tunnel_t *self);
tunnel_metadata_t getMetadataHeaderServer(void);
