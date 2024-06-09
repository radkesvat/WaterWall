#pragma once
#include "api.h"

//   upload  con -------> 
//                        HalfDuplexServer  <------>  con
//  download con <------- 

tunnel_t *        newHalfDuplexServer(node_instance_context_t *instance_info);
api_result_t      apiHalfDuplexServer(tunnel_t *self,const char *msg);
tunnel_t *        destroyHalfDuplexServer(tunnel_t *self);
tunnel_metadata_t getMetadataHalfDuplexServer(void);
