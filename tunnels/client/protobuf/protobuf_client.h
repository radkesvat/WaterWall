#pragma once
#include "api.h"

//      ---->               encode               ---->
// con                  (protocolbuffers)               con
//      <----               decode               <---- 

tunnel_t *newProtoBufClient(node_instance_context_t *instance_info);
api_result_t apiProtoBufClient(tunnel_t *self, char *msg);
tunnel_t *destroyProtoBufClient(tunnel_t *self);
tunnel_metadata_t getMetadataProtoBufClient();



