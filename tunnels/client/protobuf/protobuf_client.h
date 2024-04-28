#pragma once
#include "tunnel.h"
#include "node.h"
#include "basic_types.h"

//      ---->               encode               ---->
// con                  (protocolbuffers)               con
//      <----               decode               <----

tunnel_t         *newProtoBufClient(node_instance_context_t *instance_info);
api_result_t      apiProtoBufClient(tunnel_t *self, const char *msg);
tunnel_t         *destroyProtoBufClient(tunnel_t *self);
tunnel_metadata_t getMetadataProtoBufClient();
