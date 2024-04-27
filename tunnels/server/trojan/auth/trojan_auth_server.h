#pragma once
#include "api.h"
#include "shared/trojan/trojan_types.h"

//
//
//  con <------>  TrojanAuthServer  if (is trojan && user.found && user.enable)  <------> con
//                                  else                                         <------> fallback
//
//

tunnel_t         *newTrojanAuthServer(node_instance_context_t *instance_info);
api_result_t      apiTrojanAuthServer(tunnel_t *self, const char *msg);
tunnel_t         *destroyTrojanAuthServer(tunnel_t *self);
tunnel_metadata_t getMetadataTrojanAuthServer();
